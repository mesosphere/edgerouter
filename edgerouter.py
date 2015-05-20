#!/usr/bin/env python2

"""Updates haproxy config based on marathon.

Features:
  - Virtual Host aliases for services
  - Soft restart of haproxy
  - SSL Termination

Usage:
./edgerouter.py -m http://marathon1 -m http://marathon2:8080

HA Usage:
  TODO (Run on multiple hosts, send traffic to all)

Configuration:
  Service configuration lives in marathon via environment variables.
  The edgerouter just needs to know where to find marathon.
  To run in listening mode you must also specify the address + port at
  which the edgerouter can be reached by marathon.

  Every service port in marathon can be configured independently.

  Environment Variables:
    EDGEROUTER_{n}_GROUP
      Only edgerouter instances which are members of the given group will
      point to the service. Service routers with the gorup '*' will collect all
      groups.

    EDGEROUTER_{n}_PORT
      Forward TCP traffic from the given external port to the service. This
      gives the service its own port. May be used at the same time as VHOST.
      Ex: EDGEROUTER_0_PORT = 25

    EDGEROUTER_{n}_VHOST
      HTTP Virtual Host proxy hostname to catch
      Ex: EDGEROUTER_0_VHOST = 'marathon.mesosphere.com'

    EDGEROUTER_{n}_STICKY
      Use sticky request routing for the service
      Ex: EDGEROUTER_0_STICKY = true

    EDGEROUTER_{n}_REDIRECT_TO_HTTPS
      Redirect HTTP traffic to HTTPS
      Ex: EDGEROUTER_0_REDIRECT_TO_HTTPS = true

    EDGEROUTER_{n}_SSL_CERT
      Use the given SSL cert for TLS/SSL traffic
      Ex: EDGEROUTER_0_SSL_CERT = '/etc/ssl/certs/marathon.mesosphere.com'

    EDGEROUTER_{n}_BIND_ADDR
      Bind to the specific address for the service
      Ex: EDGEROUTER_0_BIND_ADDR = '10.0.0.42'

    EDGEROUTER_{n}_HTTPS_ON
      When Virtual Host proxying is enabled, enable / disable the service to
      be available via HTTPS. Default True.
      Ex: EDGEROUTER_0_HTTPS_ON = false

    EDGEROUTER_{n}_HTTP_ON
      When Virtual Host proxying is enabled, enable / disable the service to
      be available via HTTP. Default True.
      Ex: EDGEROUTER_0_HTTP_ON = false

Operational  Notes:
  - When a node in listening mode fails, remove the callback url for that
    node in marathon by hand.

TODO:
  More reliable way to ping, restart haproxy (Install the right reloader)
  Switch to mesos DiscoveryInfo for routing services
"""

from logging.handlers import SysLogHandler
from operator import attrgetter
from shutil import move
from tempfile import mkstemp
from textwrap import dedent
import argparse
import logging
import os.path
import re
import requests
import subprocess
import sys


class ConfigTemplater(object):
    HAPROXY_HEAD = dedent('''\
    global
      daemon
      log 127.0.0.1 local0
      log 127.0.0.1 local1 notice
      maxconn 4096

    defaults
      log               global
      retries           3
      maxconn           2000
      timeout connect   5s
      timeout client    50s
      timeout server    50s
    ''')

    HAPROXY_HTTP_FRONTEND_HEAD = dedent('''
    frontend http_in
      bind *:80
      mode http
    ''')

    # TODO(cmaloney): Allow multiple certs)
    HAPROXY_HTTPS_FRONTEND_HEAD = dedent('''
    frontend marathon_https_in
      bind *:443 ssl crt {ssl_cert}
      mode http
    ''')

    HAPROXY_FRONTEND_HEAD = dedent('''
    frontend {backend}
      bind {bindAddr}:{port}{sslCertOptions}
      mode {mode}
    ''')

    HAPROXY_BACKEND_HEAD = dedent('''
    backend {backend}
      balance roundrobin
      mode {mode}
    ''')

    HAPROXY_BACKEND_REDIRECT_HTTP_TO_HTTPS = '''\
  redirect scheme https if !{ ssl_fc }
'''

    HAPROXY_HTTP_FRONTEND_ACL = '''\
  acl host_{cleanedUpHostname} hdr(host) -i {hostname}
  use_backend {backend} if host_{cleanedUpHostname}
'''

    HAPROXY_HTTPS_FRONTEND_ACL = '''\
  use_backend {backend} if {{ ssl_fc_sni {hostname} }}
'''

    HAPROXY_BACKEND_HTTP_OPTIONS = '''\
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
'''

    HAPROXY_BACKEND_STICKY_OPTIONS = '''\
  cookie mesosphere_server_id insert indirect nocache
'''

    HAPROXY_BACKEND_SERVER_OPTIONS = '''\
  server {serverName} {host}:{port}{cookieOptions}
'''

    HAPROXY_FRONTEND_BACKEND_GLUE = '''\
  use_backend {backend}
'''

    def __init__(self, directory='templates'):
        self.__template_dicrectory = directory
        self.__load_templates()

    def __load_templates(self):
        '''Loads template files if they exist, othwerwise it sets defaults'''
        variables = [
            'HAPROXY_HEAD',
            'HAPROXY_HTTP_FRONTEND_HEAD',
            'HAPROXY_HTTPS_FRONTEND_HEAD',
            'HAPROXY_FRONTEND_HEAD',
            'HAPROXY_BACKEND_REDIRECT_HTTP_TO_HTTPS',
            'HAPROXY_BACKEND_HEAD',
            'HAPROXY_HTTP_FRONTEND_ACL',
            'HAPROXY_HTTPS_FRONTEND_ACL',
            'HAPROXY_BACKEND_HTTP_OPTIONS',
            'HAPROXY_BACKEND_STICKY_OPTIONS',
            'HAPROXY_BACKEND_SERVER_OPTIONS',
            'HAPROXY_FRONTEND_BACKEND_GLUE',
        ]

        for variable in variables:
            try:
                filename = os.path.join(self.__template_dicrectory, variable)
                with open(filename) as f:
                    logger.info('overriding %s from %s', variable, filename)
                    setattr(self, variable, f.read())
            except IOError:
                logger.debug("setting default value for %s", variable)
                try:
                    setattr(self, variable, getattr(self.__class__, variable))
                except AttributeError:
                    logger.exception('default not found, aborting.')
                    raise

    @property
    def haproxy_head(self):
        return self.HAPROXY_HEAD

    @property
    def haproxy_http_frontend_head(self):
        return self.HAPROXY_HTTP_FRONTEND_HEAD

    @property
    def haproxy_https_frontend_head(self):
        return self.HAPROXY_HTTPS_FRONTEND_HEAD

    @property
    def haproxy_frontend_head(self):
        return self.HAPROXY_FRONTEND_HEAD

    @property
    def haproxy_backend_redirect_http_to_https(self):
        return self.HAPROXY_BACKEND_REDIRECT_HTTP_TO_HTTPS

    @property
    def haproxy_backend_head(self):
        return self.HAPROXY_BACKEND_HEAD

    @property
    def haproxy_http_frontend_acl(self):
        return self.HAPROXY_HTTP_FRONTEND_ACL

    @property
    def haproxy_https_frontend_acl(self):
        return self.HAPROXY_HTTPS_FRONTEND_ACL

    @property
    def haproxy_backend_http_options(self):
        return self.HAPROXY_BACKEND_HTTP_OPTIONS

    @property
    def haproxy_backend_sticky_options(self):
        return self.HAPROXY_BACKEND_STICKY_OPTIONS

    @property
    def haproxy_backend_server_options(self):
        return self.HAPROXY_BACKEND_SERVER_OPTIONS

    @property
    def haproxy_frontend_backend_glue(self):
        return self.HAPROXY_FRONTEND_BACKEND_GLUE

variable_regex = re.compile(
        '^edgerouter_(?P<port>\d+)_(?P<name>[a-z]+)$',
        re.IGNORECASE
    )

logger = logging.getLogger('edgerouter')


class MarathonBackend(object):

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def __hash__(self):
        return hash((self.host, self.port))

    def __repr__(self):
        return "MarathonBackend(%r, %r)" % (self.host, self.port)


class MarathonService(object):

    def __init__(self, appId, portIndex, http_default, https_default):
        self.appId = appId
        self.portIndex = portIndex
        self.port = None
        self.backends = set()
        self.hostname = None
        self.sticky = False
        self.redirectHttpToHttps = False
        self.sslCert = None
        self.bindAddr = '*'
        self.groups = frozenset()
        self.httpOn = http_default
        self.httpsOn = https_default

    def add_backend(self, host, port):
        self.backends.add(MarathonBackend(host, port))

    def __hash__(self):
        return hash(self.appId, self.portIndex)

    def __eq__(self, other):
        return self.portIndex == other.portIndex and self.appId == other.appId

    def __repr__(self):
        return "MarathonService(%r, %r)" % (self.appId, self.portIndex)


def string_to_bool(s):
    return s.lower() in ["true", "t", "yes", "y"]


# Map named parameters to MarathonService member variables
def set_port(x, y):
    x.port = y


def set_hostname(x, y):
    x.hostname = y


def set_sticky(x, y):
    x.sticky = string_to_bool(y)


def redirect_http_to_https(x, y):
    x.redirectHttpToHttps = string_to_bool(y)


def sslCert(x, y):
    x.sslCert = y


def bindAddr(x, y):
    x.bindAddr = y


def httpsOn(x, y):
    x.httpsOn = string_to_bool(y)


def httpOn(x, y):
    x.httpOn = string_to_bool(y)

config_options = {
    'port': set_port,
    'vhost': set_hostname,
    'sticky': set_sticky,
    'redirect_to_https': redirect_http_to_https,
    'ssl_cert': sslCert,
    'bind_addr': bindAddr,
    'https_on': httpsOn,
    'http_on': httpOn
}


class Marathon(object):

    def __init__(self, hosts):
        # TODO(cmaloney): Support getting master list from zookeeper
        self.__hosts = hosts

    def api_req_raw(self, method, path, body=None, **kwargs):
        for host in self.__hosts:
            path_str = os.path.join(host, 'v2')
            if len(path) == 2:
                assert(path[0] == 'apps')
                path_str += '/apps/{0}'.format(path[1])
            else:
                path_str += '/' + path[0]
            response = requests.request(
                method,
                path_str,
                headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                **kwargs
            )
            if response.status_code == 200:
                break

        response.raise_for_status()
        return response

    def api_req(self, method, path, **kwargs):
        return self.api_req_raw(method, path, **kwargs).json()

    def create(self, app_json):
        return self.api_req('POST', ['apps'], app_json)

    def get_app(self, appid):
        return self.api_req('GET', ['apps', appid])["app"]

    # Lists all running apps.
    def list(self):
        return self.api_req('GET', ['apps'])["apps"]

    def tasks(self):
        return self.api_req('GET', ['tasks'])["tasks"]

    def add_subscriber(self, callbackUrl):
        return self.api_req(
                'POST',
                ['eventSubscriptions'],
                params={'callbackUrl': callbackUrl})

    def remove_subscriber(self, callbackUrl):
        return self.api_req(
                'DELETE',
                ['eventSubscriptions'],
                params={'callbackUrl': callbackUrl})


def has_group(groups, app_groups):
    # All groups / wildcard match
    if '*' in groups:
        return True

    # empty group only
    if len(groups) == 0 and len(app_groups) == 0:
        return True

    # Contains matching groups
    if (len(frozenset(app_groups) & groups)):
        return True

    return False


def config(services, ssl_cert, disable_http):
    logger.info("generating config")
    templater = ConfigTemplater()
    config = templater.haproxy_head

    if not disable_http:
        http_frontends = templater.haproxy_http_frontend_head
    if ssl_cert:
        https_frontends = templater.haproxy_https_frontend_head.format(
                ssl_cert=ssl_cert)
    frontends = str()
    backends = str()

    used_hostnames = set()

    key_func = attrgetter('appId', 'port', 'hostname')
    for service in sorted(services, key=key_func):
        if service.port is None and service.hostname is None:
            logger.info("no port or virtualhost name to listen on for app %s " +
                        "port index %d",
                        service.appId,
                        service.portIndex)
            continue

        # HAProxy wants to know if this is HTTP or TCP proxying. Default to TCP
        # proxying unless we have to do HTTP since we're doing Virtual Host
        # stuff.
        mode = 'http' if service.hostname else 'tcp'

        # Make the backend which will handle requests
        backend = "{}_{}".format(service.appId[1:].replace('/', '_'),
                                 service.portIndex)
        logger.debug("Adding backend %s for app %s port index %s",
                     backend,
                     service.appId,
                     service.portIndex)

        backend_head = templater.haproxy_backend_head
        backends += backend_head.format(
            backend=backend,
            mode=mode
        )

        if service.hostname:
            backends += templater.haproxy_backend_http_options

        if service.sticky:
            backends += templater.haproxy_backend_sticky_options

        # Add the individual running service backends.
        key_func = attrgetter('host', 'port')
        for backendServer in sorted(service.backends, key=key_func):
            logger.debug(
                "backend server at %s:%d",
                backendServer.host,
                backendServer.port)
            serverName = re.sub(
                r'[^a-zA-Z0-9\-]', '_',
                backendServer.host + '_' + str(backendServer.port))

            backend_server_options = templater.haproxy_backend_server_options
            backends += backend_server_options.format(
                host=backendServer.host,
                port=backendServer.port,
                serverName=serverName,
                cookieOptions=' check cookie ' +
                serverName if service.sticky else ''
            )

        # Add TCP/HTTP per-app port if requested
        if service.port:
            ssl_opts = ' ssl crt ' + service.sslCert if service.sslCert else ''
            frontends += templater.haproxy_frontend_head.format(
                bindAddr=service.bindAddr,
                backend=backend,
                servicePort=service.port,
                mode=mode,
                sslCertOptions=ssl_opts
            )

        # http -> https redirect
        if service.redirectHttpToHttps:
            frontends += templater.haproxy_backend_redirect_http_to_https

        # Add a Virtual Host if requested
        if service.hostname in used_hostnames:
            logger.warning("Repeated virtual host hostname %s",
                           service.hostname)
        elif service.hostname:
            used_hostnames.add(service.hostname)
            logger.debug(
                    "adding virtual host for app %s port index %s with hostname %s",
                    service.appId,
                    service.portIndex,
                    service.hostname)
            cleanedUpHostname = re.sub(r'[^a-zA-Z0-9\-]', '_', service.hostname)

            # TODO(cmaloney): Improve warning messages for HTTP
            if service.httpOn:
                if not disable_http:
                    http_frontend_acl = templater.haproxy_http_frontend_acl
                    http_frontends += http_frontend_acl.format(
                        cleanedUpHostname=cleanedUpHostname,
                        hostname=service.hostname,
                        backend=backend
                    )
                else:
                    logger.warning("HTTP Disabled but HTTP Proxying requested" +
                                   " by service %s port index %s",
                                   service.appId, service.portIndex)

            if service.httpsOn:
                if ssl_cert:
                    https_frontend_acl = templater.haproxy_https_frontend_acl
                    https_frontends += https_frontend_acl.format(
                       hostname=service.hostname,
                       backend=backend
                    )
                else:
                    logger.warning("No SSL certificate but SSL is turned on " +
                                   "for service %s port index %s",
                                   service.appId, service.portIndex)

        frontend_backend_glue = templater.haproxy_frontend_backend_glue
        frontends += frontend_backend_glue.format(backend=backend)

    if not disable_http:
        config += http_frontends
    if ssl_cert:
        config += https_frontends
    config += frontends
    config += backends

    return config


def reloadConfig():
    logger.debug("trying to find out how to reload the configuration")
    if os.path.isfile('/etc/init/haproxy.conf'):
        logger.debug("we seem to be running on an Upstart based system")
        reloadCommand = ['reload', 'haproxy']
    elif (os.path.isfile('/usr/lib/systemd/system/haproxy.service') or
            os.path.isfile('/etc/systemd/system/haproxy.service')):
        logger.debug("we seem to be running on systemd based system")
        reloadCommand = ['systemctl', 'reload', 'haproxy']
    else:
        logger.debug("we seem to be running on a sysvinit based system")
        reloadCommand = ['/etc/init.d/haproxy', 'reload']

    logger.info("reloading using %s", " ".join(reloadCommand))
    try:
        subprocess.check_call(reloadCommand)
    except OSError as ex:
        logger.error("unable to reload config using command %s",
                     " ".join(reloadCommand))
        logger.error("OSError: %s", ex)
    except subprocess.CalledProcessError as ex:
        logger.error("unable to reload config using command %s",
                     " ".join(reloadCommand))
        logger.error("reload returned non-zero: %s", ex)


def writeConfig(config, config_file):
    # Write config to a temporary location
    fd, haproxyTempConfigFile = mkstemp()
    logger.debug("writing config to temp file %s", haproxyTempConfigFile)
    with os.fdopen(fd, 'w') as haproxyTempConfig:
        haproxyTempConfig.write(config)

    # Move into place
    logger.debug("moving temp file %s to %s",
                 haproxyTempConfigFile,
                 config_file)
    move(haproxyTempConfigFile, config_file)


def compareWriteAndReloadConfig(config, config_file):
    # See if the last config on disk matches this, and if so don't reload
    # haproxy
    runningConfig = str()
    try:
        logger.debug("reading running config from %s", config_file)
        with open(config_file, "r") as f:
            runningConfig = f.read()
    except IOError:
        logger.warning("couldn't open config file for reading")

    if runningConfig != config:
        logger.info(
            "running config is different from generated config - reloading")
        writeConfig(config, config_file)
        reloadConfig()


def populate_backends(services_by_appid):
    # Populate the backends of all services by iterating through marathon tasks
    for task in marathon.tasks():
        # Early exit if no ports (no tcp or http communication possible).
        if 'ports' not in task:
            continue

        # Check the app the task belongs to has any services which should be
        # proxied.
        if task['appId'] not in services_by_appid:
            continue

        # TODO(cmaloney): If the task is from an older version of the marathon
        # app than is current, ports might not match up right.
        for idx in xrange(0, len(task['ports'])):
            if idx in services_by_appid[task['appId']]:
                services_by_appid[task['appId']][idx].add_backend(
                        task['host'],
                        task['ports'][idx])


def get_services(marathon, groups, http_default, https_default):
    # Get the per-app services defined via envrionment variables. Only services
    # valid for this host are going to be in the set (if they don't match the
    # groups they won't be present).
    services_by_appid = dict()
    for app in marathon.list():
        services_by_appid[app['id']] = dict()

        if 'env' not in app:
            continue

        # Pull out 'EDGEROUTER_{n}_{name}' config variables.
        config_by_port_index = dict()
        for env_variable, value in app.get('env', {}).iteritems():
            match = variable_regex.match(env_variable)
            if match is None:
                continue

            port_index = int(match.group(1))
            # NOTE: Make everything lower case to normalize and reduce simple
            # programmer errors.
            variable = match.group(2).lower()

            if port_index not in config_by_port_index:
                config_by_port_index[port_index] = dict()

            # Explicitly log variables we're ignoring because they're redundant.
            if variable in config_by_port_index[port_index]:
                logger.debug("Ignoring redundant EDGEROUTER variable %s " +
                             "in app %s with value %s",
                             app['id'],
                             variable,
                             value)
                continue

            # Discard unknown config parameters.
            if variable not in config_options.keys():
                logger.debug("Ignoring unknown EDGEROUTER variable %s " +
                             "in app %s",
                             app['id'],
                             variable)

            # Set the variable for later consumption into a service object.
            config_by_port_index[port_index][variable] = value

        # Process the config per port into MarathonService objects.
        for idx, config in config_by_port_index.iteritems():
            # Check if this edgerouter instance is supposed to proxy the app
            # by checking if the service is tagged with its group.
            app_groups = frozenset()
            if 'group' in config:
                app_groups = frozenset(config['group'].split(','))
            if not has_group(groups, app_groups):
                continue

            service = MarathonService(
                    app['id'],
                    idx,
                    http_default,
                    https_default)

            # Convert config parameters to member variables of MarathonService.
            # NOTE: invalid parameters have already been filtered out.
            for key, value in config.iteritems():
                config_options[key](service, value)

            # Add the MarathonService to services_by_appid
            services_by_appid[app['id']][idx] = service

    # Fill in the backends that should be forwarded to for each service.
    populate_backends(services_by_appid)

    # Flatten services to a list for easier consumption
    services = list()
    for _, services_by_idx in services_by_appid.iteritems():
        for _, service in services_by_idx.iteritems():
            services.append(service)

    return services


def regenerate_config(services, config_file, ssl_cert, disable_http):
    compareWriteAndReloadConfig(
            config(services, ssl_cert, disable_http),
            config_file)


def get_arg_parser():
    parser = argparse.ArgumentParser(
        description="Marathon HAProxy Service Router")
    parser.add_argument("--marathon", "-m",
                        required=True,
                        nargs="+",
                        help="Marathon endpoint, eg. " +
                             "-m http://marathon1:8080 " +
                             "-m http://marathon2:8080")
    log_socket = "/var/run/syslog" if sys.platform == "darwin" else "/dev/log"
    parser.add_argument("--syslog-socket",
                        help="Socket to write syslog messages to",
                        default=log_socket
                        )
    parser.add_argument("--ssl-cert",
                        help="Enables HTTP virtual host proxying." +
                             "Specifies the location of ssl cert to use for " +
                             "virtual host proxying",
                        default=None)
    parser.add_argument("--disable-http",
                        help="Disable HTTP virtual host proxying",
                        default=False,
                        action='store_true')
    parser.add_argument("--haproxy-config",
                        help="Location of haproxy configuration",
                        default="/etc/haproxy/haproxy.cfg"
                        )
    parser.add_argument("--group",
                        help="Only generate config for apps which list the "
                        "specified names. Defaults to apps without groups. "
                        "Use '*' to match all groups",
                        action="append",
                        default=list())

    return parser


def setup_logging(syslog_socket):
    logger.setLevel(logging.DEBUG)

    syslogHandler = SysLogHandler(args.syslog_socket)
    consoleHandler = logging.StreamHandler()
    formatter = logging.Formatter('%(name)s: %(message)s')
    syslogHandler.setFormatter(formatter)
    consoleHandler.setFormatter(formatter)
    # syslogHandler.setLevel(logging.ERROR)
    logger.addHandler(syslogHandler)
    logger.addHandler(consoleHandler)


if __name__ == '__main__':
    # Process arguments
    args = get_arg_parser().parse_args()

    # Setup logging
    setup_logging(args.syslog_socket)

    # Marathon API connector
    marathon = Marathon(args.marathon)

    # Generate config
    regenerate_config(
            get_services(
                marathon,
                frozenset(args.group),
                http_default=not args.disable_http,
                https_default=args.ssl_cert is not None
                ),
            args.haproxy_config,
            args.ssl_cert,
            args.disable_http)
