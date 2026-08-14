import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import hudson.FilePath
import hudson.Launcher
import hudson.model.AbstractProject
import hudson.model.Action
import hudson.model.Cause
import hudson.model.FreeStyleProject
import hudson.model.Item
import hudson.model.Job
import hudson.model.Result
import hudson.model.Run
import hudson.model.TaskListener
import hudson.model.User
import hudson.scm.ChangeLogParser
import hudson.scm.NullChangeLogParser
import hudson.scm.PollingResult
import hudson.scm.SCM
import hudson.scm.SCMRevisionState
import hudson.security.ACL
import hudson.security.AuthorizationStrategy
import hudson.security.HudsonPrivateSecurityRealm
import hudson.triggers.SCMTrigger
import hudson.triggers.TimerTrigger
import jenkins.model.Jenkins
import jenkins.security.seed.UserSeedProperty
import jenkins.triggers.ReverseBuildTrigger
import org.springframework.security.core.Authentication

class Diff002Scm extends SCM {
  @Override
  boolean requiresWorkspaceForPolling() {
    return false
  }

  @Override
  PollingResult compareRemoteRevisionWith(Job project, Launcher launcher,
                                          FilePath workspace,
                                          TaskListener listener,
                                          SCMRevisionState baseline) {
    return PollingResult.BUILD_NOW
  }

  @Override
  ChangeLogParser createChangeLogParser() {
    return NullChangeLogParser.INSTANCE
  }
}

class Diff002Acl extends ACL {
  private final String activeUserId
  private final String activeSeed
  private final String administratorUserId
  private final String administratorSeed
  private final String deletedPredecessorUserId
  private final String deletedPredecessorSeed
  private boolean deletedPredecessorRevoked = false

  Diff002Acl(String activeUserId, String activeSeed,
             String administratorUserId, String administratorSeed,
             String deletedPredecessorUserId, String deletedPredecessorSeed) {
    this.activeUserId = activeUserId
    this.activeSeed = activeSeed
    this.administratorUserId = administratorUserId
    this.administratorSeed = administratorSeed
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
    if (matchesStableIdentity(authentication, administratorUserId,
                              administratorSeed)) {
      return true
    }
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
                               String administratorUserId,
                               String administratorSeed,
                               String deletedPredecessorUserId,
                               String deletedPredecessorSeed) {
    this.rootAcl = new Diff002Acl(activeUserId, activeSeed,
                                 administratorUserId, administratorSeed,
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
def administratorUser = User.getById('diff002-admin', false)
def administratorSeed =
  administratorUser?.getProperty(UserSeedProperty.class)?.seed
assert administratorUser != null
assert administratorSeed != null
def reusedName = 'alice-reused'
def deletedPredecessorUser = User.getById(reusedName, true)
def deletedPredecessorSeed =
  deletedPredecessorUser.getProperty(UserSeedProperty.class)?.seed
assert deletedPredecessorSeed != null
def deletedPredecessor = deletedPredecessorUser.impersonate2()
def strategy = new Diff002AuthorizationStrategy(
  activeUser.id, activeSeed, administratorUser.id, administratorSeed,
  deletedPredecessorUser.id, deletedPredecessorSeed)
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
def upstream = jenkins.getItemByFullName('diff002-upstream', FreeStyleProject.class)
if (upstream == null) {
  upstream = jenkins.createProject(FreeStyleProject.class, 'diff002-upstream')
}
upstream.enable()
job.addTrigger(new ReverseBuildTrigger(upstream.fullName, Result.SUCCESS))
def timerTrigger = new TimerTrigger('@daily')
job.addTrigger(timerTrigger)
def scmTrigger = new SCMTrigger('@daily', false)
job.addTrigger(scmTrigger)
def originalScm = job.scm
job.disable()
def scmField = AbstractProject.class.getDeclaredField('scm')
scmField.accessible = true
scmField.set(job, new Diff002Scm())
def synchronousPollingField = scmTrigger.descriptor.class
  .getDeclaredField('synchronousPolling')
synchronousPollingField.accessible = true
synchronousPollingField.setBoolean(scmTrigger.descriptor, true)

def disabledIngress = [:]
def disabledIngressDetails = [:]
def targetActivity = {
  [builds: job.builds.size(),
   queued: jenkins.queue.items.count { item -> item.task == job }]
}
def activityBefore = targetActivity()
def manualResult = job.scheduleBuild2(0, new Cause.UserIdCause(administratorUser.id))
def activityAfterManual = targetActivity()
disabledIngress.manual = manualResult == null && activityAfterManual == activityBefore ?
  'deny' : 'allow'
disabledIngressDetails.manual = [
  path: 'FreeStyleProject.scheduleBuild2(UserIdCause)',
  result: disabledIngress.manual
]

def basicAuthorization = 'Basic ' +
  "${administratorUser.id}:${fixturePassword}".bytes.encodeBase64().toString()
def openJenkins = { String path, String method, Map<String, String> headers ->
  def connection = new URL("http://127.0.0.1:8080${path}").openConnection()
  connection.connectTimeout = 2_000
  connection.readTimeout = 10_000
  connection.requestMethod = method
  headers.each { name, value -> connection.setRequestProperty(name, value) }
  if (method == 'POST') {
    connection.doOutput = true
    connection.outputStream.withCloseable { output -> output.write(new byte[0]) }
  }
  return connection
}
def crumbConnection = openJenkins('/crumbIssuer/api/json', 'GET',
  [Authorization: basicAuthorization])
def crumbDocument = new JsonSlurper().parse(crumbConnection.inputStream)
crumbConnection.disconnect()
def apiConnection = openJenkins('/job/diff002-stateful/build?delay=0sec', 'POST', [
  Authorization: basicAuthorization,
  (crumbDocument.crumbRequestField.toString()): crumbDocument.crumb.toString()
])
def apiStatus = apiConnection.responseCode
try {
  (apiStatus >= 400 ? apiConnection.errorStream : apiConnection.inputStream)?.close()
} finally {
  apiConnection.disconnect()
}
def activityAfterApi = targetActivity()
disabledIngress.api = apiStatus >= 400 && activityAfterApi == activityBefore ?
  'deny' : 'allow'
disabledIngressDetails.api = [
  path: 'POST /job/diff002-stateful/build',
  http_status: apiStatus,
  result: disabledIngress.api
]

def upstreamFuture = upstream.scheduleBuild2(0,
  new Cause.UserIdCause(administratorUser.id))
assert upstreamFuture != null
def upstreamBuild = upstreamFuture.get(30, java.util.concurrent.TimeUnit.SECONDS)
Thread.sleep(250)
def activityAfterUpstream = targetActivity()
disabledIngress.upstream = upstreamBuild.result == Result.SUCCESS &&
  activityAfterUpstream == activityBefore ? 'deny' : 'allow'
disabledIngressDetails.upstream = [
  path: 'ReverseBuildTrigger after completed upstream build',
  upstream_build: upstreamBuild.number,
  upstream_result: upstreamBuild.result.toString(),
  result: disabledIngress.upstream
]

scmTrigger.run([] as Action[])
def activityAfterWebhook = targetActivity()
disabledIngress.webhook = activityAfterWebhook == activityBefore ? 'deny' : 'allow'
disabledIngressDetails.webhook = [
  path: 'SCMTrigger.run(Action[]) post-commit hook',
  result: disabledIngress.webhook
]

timerTrigger.run()
def activityAfterSchedule = targetActivity()
disabledIngress.schedule = activityAfterSchedule == activityBefore ? 'deny' : 'allow'
disabledIngressDetails.schedule = [
  path: 'TimerTrigger.run()',
  result: disabledIngress.schedule
]
def disabledPrequeueDenied = disabledIngress.values().every { it == 'deny' }
def disabledQueuedBuilds = job.builds.size() +
  jenkins.queue.items.count { item -> item.task == job }
states.add([state: job.disabled ? 'disabled' : 'enabled', generation: 2])
scmField.set(job, originalScm)
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
  disabled_ingress_details: disabledIngressDetails,
  disabled_prequeue_denied: disabledPrequeueDenied,
  disabled_queued_builds: disabledQueuedBuilds,
  rollback_admitted: rollbackAdmitted
]
println('DIFF002=' + JsonOutput.toJson(observation))
