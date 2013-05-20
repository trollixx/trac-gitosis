import os, logging
from ConfigParser import NoSectionError, NoOptionError
from fnmatch import fnmatch

from trac.env import open_environment
from trac.perm import PermissionCache

from multiproject.core.configuration import conf
from multiproject.core.proto import ProtocolManager
from multiproject.common.projects import Project

from gitosis import group

def pathMatchPatterns(path, repos):
    """
    Check existence of given path against list of path patterns

    The pattern definition is the as fnmatch.fnmatch.
    """
    for repo in repos:
        if fnmatch(path, repo):
            return True
    return False

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

    sections = ['group %s' % item for item in
                 group.getMembership(config=config, user=user)]
    sections.insert(0, 'user %s' % user)

    for sectname in sections:
        try:
            repos = config.get(sectname, mode)
        except (NoSectionError, NoOptionError):
            repos = []
        else:
            repos = repos.split()

        mapping = None

        if pathMatchPatterns(path, repos):
            log.debug(
                'Access ok for %(user)r as %(mode)r on %(path)r'
                % dict(
                user=user,
                mode=mode,
                path=path,
                ))
            mapping = path
        else:
            try:
                mapping = config.get(sectname,
                                     'map %s %s' % (mode, path))
            except (NoSectionError, NoOptionError):
                pass
            else:
                log.debug(
                    'Access ok for %(user)r as %(mode)r on %(path)r=%(mapping)r'
                    % dict(
                    user=user,
                    mode=mode,
                    path=path,
                    mapping=mapping,
                    ))

        if mapping is not None:
            prefix = None
            try:
                prefix = config.get(sectname, 'repositories')
            except (NoSectionError, NoOptionError):
                try:
                    prefix = config.get('gitosis', 'repositories')
                except (NoSectionError, NoOptionError):
                    prefix = 'repositories'

            log.debug(
                'Using prefix %(prefix)r for %(path)r'
                % dict(
                prefix=prefix,
                path=mapping,
                ))
            return (prefix, mapping)

    # PATCH: Authenticate against MultiProject backend(s)

    if path.startswith('git/'):
        path = path[4:]
    project_name = path

    env = open_environment(conf.getEnvironmentSysPath(project_name), use_cache=True)

    # Ensure project is using git repo
    if env.config.get('trac', 'repository_type', default='') != 'git':
        return None

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
    if not protocols.is_protocol_allowed('ssh', 'git'):
        return None

    # Check permissions
    if action in PermissionCache(env, username=user):
        env.log.info('Granted Gitosis access for %s as %s on %s' % (user, mode, path))

        # Get the prefix and mapping
        vcs_path = conf.getEnvironmentVcsPath(project_name)
        if vcs_path:
            mapping = path
            prefix = os.path.dirname(vcs_path)
            log.debug('Using prefix %(prefix)r for %(path)r' %
                      dict(prefix=prefix, path=mapping,))
            return prefix, mapping
    else:
        env.log.warning('Unauthorized access for %s as %s on %s' % (user, mode, path))
