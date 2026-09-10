// Disposable JCOMP-003 observation driver. Executes unchanged positive sources only.
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import jenkins.model.Jenkins
import hudson.tasks.Shell
import org.jenkinsci.plugins.workflow.job.WorkflowJob
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition
import org.jenkinsci.plugins.workflow.graphanalysis.DepthFirstScanner
import org.jenkinsci.plugins.workflow.graph.BlockEndNode
import org.jenkinsci.plugins.workflow.actions.ArgumentsAction
import org.jenkinsci.plugins.workflow.actions.ErrorAction
import org.jenkinsci.plugins.workflow.actions.LabelAction
import org.jenkinsci.plugins.workflow.actions.LogAction
import org.jenkinsci.plugins.workflow.actions.TimingAction
import org.jenkinsci.plugins.workflow.actions.TagsAction
import java.nio.file.Files
import java.nio.file.LinkOption
import java.security.MessageDigest

def j = Jenkins.get()
j.setNumExecutors(1)
j.getDescriptorByType(Shell.DescriptorImpl).setShell('/opt/jcomp/observe-shell')
j.save()
def output = new File('/tmp/jcomp-observations')
output.mkdirs()
def writeJson = { String name, Object value ->
    new File(output, name).setText(JsonOutput.prettyPrint(JsonOutput.toJson(value)) + '\n', 'UTF-8')
}
def sha = { byte[] bytes -> MessageDigest.getInstance('SHA-256').digest(bytes).encodeHex().toString() }
def inventory = { java.nio.file.Path root ->
  def entries = []
  if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
    def stream = Files.walk(root)
    try {
      stream.forEach { path ->
        if (path != root) {
          def relative = root.relativize(path).toString()
          if (Files.isSymbolicLink(path)) { entries << [path:relative, kind:'symlink', target:Files.readSymbolicLink(path).toString()] }
          else if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) { entries << [path:relative, kind:'directory'] }
          else if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            byte[] bytes = Files.readAllBytes(path)
            entries << [path:relative, kind:'file', size_bytes:bytes.length, sha256:sha(bytes), contents_base64:bytes.encodeBase64().toString()]
          } else { entries << [path:relative, kind:'special'] }
        }
      }
    } finally { stream.close() }
  }
  entries.sort {it.path}
}
Thread.start('jcomp003-contained-observer') {
  try {
    while (j.getInitLevel().toString() != 'COMPLETED') { Thread.sleep(100) }
    def approval = new File('/tmp/jcomp-boundary-approved')
    def approvalDeadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(60)
    while (!approval.exists() && System.nanoTime() < approvalDeadline) { Thread.sleep(100) }
    assert approval.isFile(): 'disposable boundary was not approved'
    def manifest = new JsonSlurper().parse(new File('/opt/jcomp/input/manifest.json'))
    def profile = new Properties()
    new File('/opt/jcomp/input/profile-v1.properties').withInputStream { profile.load(it) }
    def coreJar = new File(Jenkins.protectionDomain.codeSource.location.toURI())
    def groovyJar = new File(GroovySystem.protectionDomain.codeSource.location.toURI())
    assert sha(coreJar.bytes) == profile.getProperty('jenkins.core.jar.sha256')
    assert sha(groovyJar.bytes) == profile.getProperty('groovy.jar.sha256')
    assert sha(new File('/usr/share/jenkins/jenkins.war').bytes) == profile.getProperty('jenkins.war.sha256')
    assert Jenkins.VERSION == profile.getProperty('jenkins.core.version')
    assert GroovySystem.version == profile.getProperty('groovy.version')
    assert System.getProperty('java.runtime.version') == profile.getProperty('java.runtime.version')
    assert System.getProperty('java.vendor') == profile.getProperty('java.vendor')
    assert System.getenv('JCOMP_STEP_SENTINEL') == null
    def pluginPins = new File('/opt/jcomp/input/PLUGIN_SHA256SUMS').readLines('UTF-8').collectEntries { line ->
      def fields = line.split(/\s+/)
      [(fields[1].substring('plugins/'.length())): fields[0]]
    }
    assert pluginPins.size() == 90
    assert new File('/var/jenkins_home/plugins').listFiles().findAll {it.name.endsWith('.jpi')}*.name.sort() == pluginPins.keySet().sort()
    pluginPins.each { filename, digest -> assert sha(new File('/var/jenkins_home/plugins/' + filename).bytes) == digest }
    assert j.pluginManager.plugins.size() == 90
    assert j.pluginManager.plugins.every {it.active}
    def results = []
    writeJson('runtime.json', [jenkins: Jenkins.VERSION, java: System.getProperty('java.runtime.version'),
      java_vendor: System.getProperty('java.vendor'), groovy: GroovySystem.version,
      core_jar_path:coreJar.path, core_jar_sha256:sha(coreJar.bytes),
      groovy_jar_path:groovyJar.path, groovy_jar_sha256:sha(groovyJar.bytes),
      war_sha256:sha(new File('/usr/share/jenkins/jenkins.war').bytes),
      plugin_files:pluginPins, step_sentinel_initially_absent:true,
      plugins: j.pluginManager.plugins.collect { [short_name: it.shortName, version: it.version, active: it.active] }.sort {it.short_name},
      shell: j.getDescriptorByType(Shell.DescriptorImpl).shell])
    manifest.fixtures.findAll { it.expected.compilation == 'supported' }.each { fixture ->
      def id = fixture.id
      def sourceFile = new File('/opt/jcomp/input/' + id + '.Jenkinsfile')
      assert sha(sourceFile.bytes) == fixture.source_sha256
      def beforeShells = output.listFiles().findAll { it.name.startsWith('shell.') }*.name as Set
      def job = j.createProject(WorkflowJob, 'jcomp-' + id)
      job.setDefinition(new CpsFlowDefinition(sourceFile.getText('UTF-8'), false))
      job.save()
      // Observer-owned explicit anonymous cause fixes the retained console header.
      def cause = new hudson.model.CauseAction(new hudson.model.Cause.UserIdCause((String) null))
      def build = job.scheduleBuild2(0, cause).get(90, java.util.concurrent.TimeUnit.SECONDS)
      assert !build.isBuilding()
      def rawLog = build.getLogFile().bytes
      new File(output, id + '.console').bytes = rawLog
      def plainLog = new ByteArrayOutputStream()
      build.getLogText().writeLogTo(0, plainLog)
      byte[] consoleText = plainLog.toByteArray()
      new File(output, id + '.console-text').bytes = consoleText
      def nodes = new DepthFirstScanner().allNodes(build.execution).collect { node ->
        def action = node.getAction(LogAction)
        def log = new ByteArrayOutputStream()
        if (action != null) { action.getLogText().writeLogTo(0, log) }
        def err = node.getAction(ErrorAction)
        [id: node.id, parents: node.parents*.id, display_name: node.displayName,
         type: node.class.name, function_name: node.displayFunctionName,
         arguments: ArgumentsAction.getResolvedArguments(node) ?: [:],
         block_start_id: node instanceof BlockEndNode ? node.startNode.id : null,
         label: node.getAction(LabelAction)?.displayName,
         tags: node.getAction(TagsAction)?.tags ?: [:],
         start_ms: TimingAction.getStartTime(node),
         error: err == null ? null : [type:err.error.class.name, message:err.error.message],
         log_base64: log.toByteArray().encodeBase64().toString(),
         actions: node.getAllActions().collect {it.class.name}]
      }
      def workspace = j.getWorkspaceFor(job)
      def workspacePath = new File(workspace.remote).toPath()
      def entries = inventory(workspacePath)
      def control = new File(workspace.remote + '@tmp')
      def shells = output.listFiles().findAll { it.name.startsWith('shell.') && !beforeShells.contains(it.name) }.collect { it.name }.sort()
      def record = [fixture:id, source_sha256:sha(sourceFile.bytes), build:build.number,
        result:build.result.toString(), start_ms:build.startTimeInMillis, duration_ms:build.duration,
        nodes:nodes, workspace:entries, control_entries:inventory(control.toPath()), shells:shells,
        workspace_path:workspace.remote, console_sha256:sha(rawLog),
        console_text_sha256:sha(consoleText)]
      // Persist measured outputs before deleting any workspace or job state.
      writeJson(id + '.json', record)
      workspace.deleteRecursive()
      record.workspace_cleanup = !workspace.exists()
      if (control.exists()) { new hudson.FilePath(control).deleteRecursive() }
      record.control_cleanup = !control.exists()
      assert record.workspace_cleanup && record.control_cleanup
      writeJson(id + '.json', record)
      results << [fixture:id, result:record.result]
    }
    assert j.queue.items.length == 0
    writeJson('complete.json', [schema:'mcloving.jenkins.sequential-observations/1', results:results, queue:0, production_authority:false])
  } catch (Throwable error) {
    def sw = new StringWriter()
    error.printStackTrace(new PrintWriter(sw))
    new File(output, 'failure.txt').setText(sw.toString(), 'UTF-8')
  }
}
