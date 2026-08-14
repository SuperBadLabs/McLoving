import groovy.json.JsonOutput
import hudson.model.FreeStyleProject
import hudson.model.Item
import hudson.model.Result
import hudson.model.User
import hudson.security.ACL
import hudson.security.AuthorizationStrategy
import hudson.security.HudsonPrivateSecurityRealm
import jenkins.model.Jenkins
import org.springframework.security.core.Authentication

class Diff002Acl extends ACL {
  private final Authentication active
  private final Authentication deletedPredecessor

  Diff002Acl(Authentication active, Authentication deletedPredecessor) {
    this.active = active
    this.deletedPredecessor = deletedPredecessor
  }

  @Override
  boolean hasPermission2(Authentication authentication, hudson.security.Permission permission) {
    if (authentication == null) {
      return false
    }
    if (authentication.is(active) || authentication.is(deletedPredecessor)) {
      return permission == Jenkins.READ || permission == Item.READ
    }
    return false
  }
}

class Diff002AuthorizationStrategy extends AuthorizationStrategy {
  private final ACL rootAcl

  Diff002AuthorizationStrategy(Authentication active, Authentication deletedPredecessor) {
    this.rootAcl = new Diff002Acl(active, deletedPredecessor)
  }

  @Override
  ACL getRootACL() {
    return rootAcl
  }

  @Override
  Collection<String> getGroups() {
    return Collections.emptySet()
  }
}

def jenkins = Jenkins.get()
def job = jenkins.getItemByFullName('diff002-stateful', FreeStyleProject.class)
if (job == null) {
  job = jenkins.createProject(FreeStyleProject.class, 'diff002-stateful')
}
job.enable()

def active = User.getById('jenkins-user-immutable-1042', false).impersonate2()
def reusedName = 'alice-reused'
def deletedPredecessorUser = User.getById(reusedName, false)
def deletedPredecessor = deletedPredecessorUser.impersonate2()
def strategy = new Diff002AuthorizationStrategy(active, deletedPredecessor)
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
deletedPredecessorUser.delete()
def deletedPredecessorRemoved = User.getById(reusedName, false) == null
def realm = jenkins.securityRealm as HudsonPrivateSecurityRealm
def fixturePassword = new File('/run/secrets/diff002-admin-password').text.trim()
realm.createAccount(reusedName, fixturePassword)
def deletedReuseUser = User.getById(reusedName, false)
def deletedReuse = deletedReuseUser.impersonate2()
def reuseIdentityChanged = !deletedPredecessor.is(deletedReuse)

def states = [[state: job.disabled ? 'disabled' : 'enabled', generation: 1]]
job.disable()
def disabledPrequeueDenied = job.scheduleBuild2(0) == null
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
  decisions: decisions(active),
  deleted_reuse_name: reusedName,
  deleted_predecessor_immutable_id: 'jenkins-user-deleted-2041',
  deleted_predecessor_decisions: deletedPredecessorDecisions,
  deleted_predecessor_deleted: deletedPredecessorRemoved,
  deleted_reuse_immutable_id: 'jenkins-user-deleted-reuse-2042',
  deleted_reuse_decisions: decisions(deletedReuse),
  deleted_reuse_authentication_changed: reuseIdentityChanged,
  states: states,
  disabled_prequeue_denied: disabledPrequeueDenied,
  rollback_admitted: rollbackAdmitted
]
println('DIFF002=' + JsonOutput.toJson(observation))
