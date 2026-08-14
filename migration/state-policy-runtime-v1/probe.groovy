import groovy.json.JsonOutput
import hudson.model.FreeStyleProject
import hudson.model.Item
import hudson.model.Result
import hudson.model.User
import hudson.security.ACL
import hudson.security.AuthorizationStrategy
import hudson.security.HudsonPrivateSecurityRealm
import jenkins.model.Jenkins
import jenkins.security.seed.UserSeedProperty
import org.springframework.security.core.Authentication

class Diff002Acl extends ACL {
  private final String activeUserId
  private final String activeSeed
  private final String deletedPredecessorUserId
  private final String deletedPredecessorSeed
  private boolean deletedPredecessorRevoked = false

  Diff002Acl(String activeUserId, String activeSeed,
             String deletedPredecessorUserId, String deletedPredecessorSeed) {
    this.activeUserId = activeUserId
    this.activeSeed = activeSeed
    this.deletedPredecessorUserId = deletedPredecessorUserId
    this.deletedPredecessorSeed = deletedPredecessorSeed
  }

  private static boolean matchesStableIdentity(Authentication authentication,
                                               String userId, String seed) {
    if (authentication == null || authentication.name != userId) {
      return false
    }
    def current = User.getById(userId, false)
    def currentSeed = current?.getProperty(UserSeedProperty.class)?.seed
    return currentSeed != null && currentSeed == seed
  }

  @Override
  boolean hasPermission2(Authentication authentication, hudson.security.Permission permission) {
    if (matchesStableIdentity(authentication, activeUserId, activeSeed)
        || (!deletedPredecessorRevoked
            && matchesStableIdentity(authentication, deletedPredecessorUserId,
                                     deletedPredecessorSeed))) {
      return permission == Jenkins.READ || permission == Item.READ
    }
    return false
  }

  void revokeDeletedPredecessor() {
    deletedPredecessorRevoked = true
  }
}

class Diff002AuthorizationStrategy extends AuthorizationStrategy {
  private final ACL rootAcl

  Diff002AuthorizationStrategy(String activeUserId, String activeSeed,
                               String deletedPredecessorUserId,
                               String deletedPredecessorSeed) {
    this.rootAcl = new Diff002Acl(activeUserId, activeSeed,
                                 deletedPredecessorUserId, deletedPredecessorSeed)
  }

  @Override
  ACL getRootACL() {
    return rootAcl
  }

  @Override
  Collection<String> getGroups() {
    return Collections.emptySet()
  }

  void revokeDeletedPredecessor() {
    (rootAcl as Diff002Acl).revokeDeletedPredecessor()
  }
}

def jenkins = Jenkins.get()
def job = jenkins.getItemByFullName('diff002-stateful', FreeStyleProject.class)
if (job == null) {
  job = jenkins.createProject(FreeStyleProject.class, 'diff002-stateful')
}
job.enable()

def activeUser = User.getById('jenkins-user-immutable-1042', true)
def activeSeed = activeUser.getProperty(UserSeedProperty.class)?.seed
assert activeSeed != null
def active = activeUser.impersonate2()
def activeFresh = activeUser.impersonate2()
def reusedName = 'alice-reused'
def deletedPredecessorUser = User.getById(reusedName, true)
def deletedPredecessorSeed =
  deletedPredecessorUser.getProperty(UserSeedProperty.class)?.seed
assert deletedPredecessorSeed != null
def deletedPredecessor = deletedPredecessorUser.impersonate2()
def strategy = new Diff002AuthorizationStrategy(
  activeUser.id, activeSeed, deletedPredecessorUser.id, deletedPredecessorSeed)
def strategyField = Jenkins.class.getDeclaredField('authorizationStrategy')
strategyField.accessible = true
strategyField.set(jenkins, strategy)
def decisions = { authentication ->
  def installedAcl = job.getACL()
  [
    project_view: installedAcl.hasPermission2(authentication, Item.READ) ? 'allow' : 'deny',
    build_trigger: installedAcl.hasPermission2(authentication, Item.BUILD) ? 'allow' : 'deny',
    build_cancel: installedAcl.hasPermission2(authentication, Item.CANCEL) ? 'allow' : 'deny',
    project_configure: installedAcl.hasPermission2(authentication, Item.CONFIGURE) ? 'allow' : 'deny'
  ]
}
def deletedPredecessorDecisions = decisions(deletedPredecessor)
def activeDecisions = decisions(active)
def activeFreshDecisions = decisions(activeFresh)
def activeAuthenticationIdentityStable =
  !active.is(activeFresh) && activeDecisions == activeFreshDecisions
deletedPredecessorUser.delete()
def deletedPredecessorRemoved = User.getById(reusedName, false) == null
strategy.revokeDeletedPredecessor()
def deletedPredecessorPostDeleteDecisions = decisions(deletedPredecessor)
def realm = jenkins.securityRealm as HudsonPrivateSecurityRealm
def fixturePassword = new File('/run/secrets/diff002-admin-password').text.trim()
realm.createAccount(reusedName, fixturePassword)
def deletedReuseUser = User.getById(reusedName, true)
def deletedReuseSeed = deletedReuseUser.getProperty(UserSeedProperty.class)?.seed
assert deletedReuseSeed != null
def deletedReuse = deletedReuseUser.impersonate2()
def reuseIdentityChanged = deletedPredecessorSeed != deletedReuseSeed

def states = [[state: job.disabled ? 'disabled' : 'enabled', generation: 1]]
job.disable()
def disabledIngress = [:]
['manual', 'api', 'upstream', 'webhook', 'schedule'].each { kind ->
  disabledIngress[kind] = job.scheduleBuild2(0) == null ? 'deny' : 'allow'
}
def disabledPrequeueDenied = disabledIngress.values().every { it == 'deny' }
def disabledQueuedBuilds = job.builds.size() +
  jenkins.queue.items.count { item -> item.task == job }
states.add([state: job.disabled ? 'disabled' : 'enabled', generation: 2])
job.enable()
states.add([state: job.disabled ? 'disabled' : 'enabled', generation: 3])
def admitted = job.scheduleBuild2(0)
def rollbackAdmitted = admitted != null
if (admitted != null) {
  admitted.cancel(true)
}

def observation = [
  schema: 'mcloving.diff002.jenkins-runtime/v1',
  security_realm: jenkins.securityRealm.class.name,
  authorization_strategy: jenkins.authorizationStrategy.class.simpleName,
  installed_acl: job.getACL().class.simpleName,
  immutable_id: 'jenkins-user-immutable-1042',
  decisions: activeDecisions,
  fresh_authentication_decisions: activeFreshDecisions,
  authentication_identity_stable: activeAuthenticationIdentityStable,
  deleted_reuse_name: reusedName,
  deleted_predecessor_immutable_id: 'jenkins-user-deleted-2041',
  deleted_predecessor_decisions: deletedPredecessorDecisions,
  deleted_predecessor_deleted: deletedPredecessorRemoved,
  deleted_predecessor_post_delete_decisions: deletedPredecessorPostDeleteDecisions,
  deleted_reuse_immutable_id: 'jenkins-user-deleted-reuse-2042',
  deleted_reuse_decisions: decisions(deletedReuse),
  deleted_reuse_authentication_changed: reuseIdentityChanged,
  states: states,
  disabled_ingress: disabledIngress,
  disabled_prequeue_denied: disabledPrequeueDenied,
  disabled_queued_builds: disabledQueuedBuilds,
  rollback_admitted: rollbackAdmitted
]
println('DIFF002=' + JsonOutput.toJson(observation))
