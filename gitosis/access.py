import os, logging
from ConfigParser import NoSectionError, NoOptionError

from trac.env import open_environment
from trac.perm import PermissionCache

from multiproject.core.configuration import Configuration
from multiproject.core.proto import ProtocolManager
from multiproject.common.projects import Project

from gitosis import group

conf = Configuration.instance()

def haveAccess(config, user, mode, path):
    """
    Map request for write access to allowed path.

    Note for read-only access, the caller should check for write
    access too.

    Returns ``None`` for no access, or a tuple of toplevel directory
    containing repositories and a relative path to the physical repository.
    """
    log = logging.getLogger('gitosis.access.haveAccess')

    log.debug(
        'Access check for %(user)r as %(mode)r on %(path)r...'
        % dict(
        user=user,
        mode=mode,
        path=path,
        ))

    basename, ext = os.path.splitext(path)
    if ext == '.git':
        log.debug(
            'Stripping .git suffix from %(path)r, new value %(basename)r'
            % dict(
            path=path,
            basename=basename,
            ))
        path = basename

    # PATCH: Authenticate against MultiProject backend(s)

    project_name = path.split('/')[0]

    env = open_environment(conf.getEnvironmentSysPath(project_name), use_cache=True)

    # Map the mode to the action.
    action = None
    if mode == 'readonly':
        action = 'VERSION_CONTROL_VIEW'
    elif mode in ('writable', 'writeable'):
        action = 'VERSION_CONTROL'
    else:
        return None

    # Check if protocol is allowed or not
    project = Project.get(env)
    protocols = ProtocolManager(project.id)

    # Check permissions
    if action in PermissionCache(env, username=user):
        env.log.info('Granted Gitosis access for %s as %s on %s' % (user, mode, path))

        # Get the prefix and mapping
        vcs_path = conf.getEnvironmentVcsPath(path.split('/')[0], 'git', path.split('/')[-1])
        if vcs_path:
            mapping = path.split('/')[-1]
            prefix = os.path.dirname(vcs_path)
            #conf.log.exception('Using prefix %(prefix)r for %(path)r' % dict(prefix=prefix, path=mapping,))
            return prefix, mapping
    else:
        env.log.warning('Unauthorized access for %s as %s on %s' % (user, mode, path))
