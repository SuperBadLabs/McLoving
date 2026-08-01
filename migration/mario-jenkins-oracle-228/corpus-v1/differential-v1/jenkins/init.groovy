import jenkins.model.Jenkins
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition
import org.jenkinsci.plugins.workflow.job.WorkflowJob

def jenkins = Jenkins.get()
jenkins.setNumExecutors(1)
jenkins.setCrumbIssuer(null)
jenkins.save()

def jobName = 'diff-001-admitted'
def source = new File('/fixture/Jenkinsfile').getText('UTF-8')
def existing = jenkins.getItem(jobName)
if (existing != null && !(existing instanceof WorkflowJob)) {
    throw new IllegalStateException("unexpected existing item ${jobName}")
}
def job = existing ?: jenkins.createProject(WorkflowJob, jobName)
job.setDefinition(new CpsFlowDefinition(source, true))
job.setDisabled(false)
job.save()
