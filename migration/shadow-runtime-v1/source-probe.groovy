import groovy.json.JsonOutput
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.domains.DomainRequirement
import hudson.model.Action
import hudson.model.Cause
import hudson.model.CauseAction
import hudson.model.Job
import hudson.model.Result
import hudson.model.Run
import hudson.model.TaskListener
import hudson.model.Item
import hudson.model.ItemGroup
import hudson.triggers.SCMTrigger
import hudson.triggers.TimerTrigger
import jenkins.model.Jenkins
import jenkins.triggers.ReverseBuildTrigger
import jenkins.util.TimeDuration
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition
import org.jenkinsci.plugins.workflow.job.WorkflowJob
import org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty
import org.kohsuke.stapler.HttpResponses
import org.kohsuke.stapler.StaplerRequest2
import org.kohsuke.stapler.StaplerResponse2
import org.acegisecurity.Authentication as AcegiAuthentication
import org.springframework.security.core.Authentication as SpringAuthentication

class ShadowCredentialObserver extends CredentialsProvider {
  final java.util.concurrent.atomic.AtomicLong lookups =
    new java.util.concurrent.atomic.AtomicLong()

  @Override
  List getCredentials(Class type, ItemGroup itemGroup,
      AcegiAuthentication authentication, List<DomainRequirement> requirements) {
    lookups.incrementAndGet()
    []
  }

  @Override
  List getCredentials(Class type, Item item,
      AcegiAuthentication authentication, List<DomainRequirement> requirements) {
    lookups.incrementAndGet()
    []
  }

  @Override
  List getCredentialsInItemGroup(Class type, ItemGroup itemGroup,
      SpringAuthentication authentication, List<DomainRequirement> requirements) {
    lookups.incrementAndGet()
    []
  }

  @Override
  List getCredentialsInItem(Class type, Item item,
      SpringAuthentication authentication, List<DomainRequirement> requirements) {
    lookups.incrementAndGet()
    []
  }
}

def schema = 'mcloving.shadow001.jenkins-source-probe/v1'
def jobName = 'corpus-052-cinqict_jenkinsdev'
def jenkins = Jenkins.get()
def job = jenkins.getItemByFullName(jobName, WorkflowJob.class)
assert job != null
assert job.disabled
assert job.triggers.isEmpty()
assert job.definition instanceof CpsFlowDefinition
def sha256 = { byte[] bytes ->
  java.security.MessageDigest.getInstance('SHA-256')
    .digest(bytes).encodeHex().toString()
}
def definitionKind = job.definition.class.name
def sourceSha256 = sha256(job.definition.script.getBytes(java.nio.charset.StandardCharsets.UTF_8))
def sourceConfigSha256 = sha256(job.getConfigFile().getFile().bytes)
def originalTriggerProperty =
  job.getProperty(PipelineTriggersJobProperty.class)
def scmPollingLog = new File(job.rootDir, 'scm-polling.log')
def originalScmPollingLogExists = scmPollingLog.exists()
def originalScmPollingLog = originalScmPollingLogExists ? scmPollingLog.bytes : null
def originalScmPollingLogSha256 =
  originalScmPollingLogExists ? sha256(originalScmPollingLog) : null
def originalScmPollingLogModified = originalScmPollingLogExists ? scmPollingLog.lastModified() : 0L
def credentialObserver = new ShadowCredentialObserver()
def credentialProviders = CredentialsProvider.all()
credentialProviders.add(credentialObserver)

def activity = {
  [
    builds: job.builds.size(),
    queued: jenkins.queue.items.count { item -> item.task == job },
    next_build_number: job.nextBuildNumber,
    credential_lookups: credentialObserver.lookups.get()
  ]
}
def original = activity()
def capturedWallClockUnixMs = System.currentTimeMillis()
def results = []
def installedTriggers = []

def record = { kind, path, accepted, before, after, detail ->
  results.add([
    kind: kind,
    path: path,
    outcome: !accepted && before == after ? 'disabled_pre_queue' : 'unexpected_activity',
    queued_builds: after.queued,
    scheduled_attempts: after.builds - original.builds,
    credential_grants: after.credential_lookups - before.credential_lookups,
    detail: detail
  ])
}

try {
  def before = activity()
  def apiAccepted = false
  def apiRejection = null
  try {
    def apiFuture = job.doBuild((StaplerRequest2) null, (StaplerResponse2) null,
      new TimeDuration(0))
    apiAccepted = apiFuture != null
  } catch (HttpResponses.HttpResponseException exception) {
    apiRejection = exception.class.name
  }
  def after = activity()
  record('api', 'WorkflowJob.doBuild(StaplerRequest2,StaplerResponse2,TimeDuration)',
    apiAccepted, before, after, [rejection: apiRejection])

  before = activity()
  def manualFuture = job.scheduleBuild2(
    0, new CauseAction(new Cause.UserIdCause('oracle-admin')))
  after = activity()
  record('manual', 'WorkflowJob.scheduleBuild2(UserIdCause)', manualFuture != null,
    before, after, [returned_future: manualFuture != null])

  def timerTrigger = new TimerTrigger('@daily')
  job.addTrigger(timerTrigger)
  installedTriggers.add(timerTrigger)
  before = activity()
  timerTrigger.run()
  after = activity()
  record('schedule', 'TimerTrigger.run()', false, before, after, [:])

  def completedUpstream = jenkins.getAllItems(Job.class)
    .findAll { candidate -> candidate != job }
    .collectMany { candidate -> candidate.builds }
    .find { build -> build.result != null }
  assert completedUpstream != null
  def upstreamTrigger = new ReverseBuildTrigger(
    completedUpstream.parent.fullName, completedUpstream.result)
  job.addTrigger(upstreamTrigger)
  installedTriggers.add(upstreamTrigger)
  before = activity()
  new ReverseBuildTrigger.RunListenerImpl().onCompleted(
    (Run) completedUpstream, TaskListener.NULL)
  after = activity()
  record('upstream', 'ReverseBuildTrigger.RunListenerImpl.onCompleted', false,
    before, after, [upstream_result: completedUpstream.result.toString()])

  def scmTrigger = new SCMTrigger('@daily', false)
  job.addTrigger(scmTrigger)
  installedTriggers.add(scmTrigger)
  before = activity()
  scmTrigger.run([] as Action[])
  after = activity()
  record('webhook', 'SCMTrigger.run(Action[])', false, before, after, [:])
} finally {
  def triggerProperty = job.getProperty(PipelineTriggersJobProperty.class)
  installedTriggers.reverseEach { trigger ->
    triggerProperty?.removeTrigger(trigger)
  }
  if (originalTriggerProperty == null &&
      job.getProperty(PipelineTriggersJobProperty.class) != null &&
      job.triggers.isEmpty()) {
    job.removeProperty(PipelineTriggersJobProperty.class)
  }
  if (originalScmPollingLogExists) {
    scmPollingLog.bytes = originalScmPollingLog
    assert scmPollingLog.setLastModified(originalScmPollingLogModified)
  } else if (scmPollingLog.exists()) {
    assert scmPollingLog.delete()
  }
  credentialProviders.remove(credentialObserver)
}

def terminal = activity()
def terminalSourceSha256 = sha256(
  job.definition.script.getBytes(java.nio.charset.StandardCharsets.UTF_8))
def terminalSourceConfigSha256 = sha256(job.getConfigFile().getFile().bytes)
assert terminal == original
assert job.disabled
assert job.triggers.isEmpty()
assert job.definition.class.name == definitionKind
assert terminalSourceSha256 == sourceSha256
assert terminalSourceConfigSha256 == sourceConfigSha256
assert scmPollingLog.exists() == originalScmPollingLogExists
assert !originalScmPollingLogExists ||
  sha256(scmPollingLog.bytes) == originalScmPollingLogSha256
assert !originalScmPollingLogExists || scmPollingLog.lastModified() == originalScmPollingLogModified
assert results*.kind == ['api', 'manual', 'schedule', 'upstream', 'webhook']
assert results.every { result -> result.outcome == 'disabled_pre_queue' }

println('SHADOW001_SOURCE=' + JsonOutput.toJson([
  schema: schema,
  job_id: jobName,
  source_state: 'disabled',
  definition_kind: definitionKind,
  source_sha256: sourceSha256,
  source_config_sha256: sourceConfigSha256,
  captured_wall_clock_unix_ms: capturedWallClockUnixMs,
  original_activity: original,
  terminal_activity: terminal,
  observations: results
]))
