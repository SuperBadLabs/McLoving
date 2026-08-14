import groovy.json.JsonOutput
import hudson.model.FreeStyleProject
import hudson.model.Item
import hudson.model.Result
import hudson.model.User
import hudson.security.ACL
import jenkins.model.Jenkins
import org.springframework.security.core.Authentication

class Diff002Acl extends ACL {
  @Override
  boolean hasPermission2(Authentication authentication, hudson.security.Permission permission) {
    if (authentication == null) {
      return false
    }
    if (authentication.name == 'jenkins-user-immutable-1042') {
      return permission == Jenkins.READ || permission == Item.READ
    }
    return false
  }
}

def jenkins = Jenkins.get()
def job = jenkins.getItemByFullName('diff002-stateful', FreeStyleProject.class)
if (job == null) {
  job = jenkins.createProject(FreeStyleProject.class, 'diff002-stateful')
}
job.enable()

def active = User.getById('jenkins-user-immutable-1042', false).impersonate2()
def deletedReuse = User.getById('jenkins-user-deleted-reuse-2042', false).impersonate2()
def fixtureAcl = new Diff002Acl()
def decisions = { authentication ->
  [
    project_view: fixtureAcl.hasPermission2(authentication, Item.READ) ? 'allow' : 'deny',
    build_trigger: fixtureAcl.hasPermission2(authentication, Item.BUILD) ? 'allow' : 'deny',
    build_cancel: fixtureAcl.hasPermission2(authentication, Item.CANCEL) ? 'allow' : 'deny',
    project_configure: fixtureAcl.hasPermission2(authentication, Item.CONFIGURE) ? 'allow' : 'deny'
  ]
}

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
  immutable_id: 'jenkins-user-immutable-1042',
  decisions: decisions(active),
  deleted_reuse_immutable_id: 'jenkins-user-deleted-reuse-2042',
  deleted_reuse_decisions: decisions(deletedReuse),
  states: states,
  disabled_prequeue_denied: disabledPrequeueDenied,
  rollback_admitted: rollbackAdmitted
]
println('DIFF002=' + JsonOutput.toJson(observation))
