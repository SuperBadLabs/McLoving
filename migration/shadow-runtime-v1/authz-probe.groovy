import groovy.json.JsonOutput
import hudson.model.Item
import hudson.model.User
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import jenkins.model.Jenkins
import jenkins.security.seed.UserSeedProperty
import org.jenkinsci.plugins.workflow.job.WorkflowJob

def jenkins = Jenkins.get()
def job = jenkins.getItemByFullName(
  'corpus-052-cinqict_jenkinsdev', WorkflowJob.class)
def user = User.getById('oracle-admin', false)
def seed = user?.getProperty(UserSeedProperty.class)?.seed
assert job != null
assert job.disabled
assert user != null
assert seed != null && !seed.isEmpty()

def authentication = user.impersonate2()
def sha256 = { byte[] bytes ->
  MessageDigest.getInstance('SHA-256')
    .digest(bytes).encodeHex().toString()
}
def binding = [
  schema: 'mcloving.shadow001.jenkins-authz-generation/v1',
  source_controller: 'mario/jenkins-oracle-228',
  inventory_epoch: 'mario-oracle-20260731T064417Z-r2',
  job_id: job.fullName,
  job_disabled: job.disabled,
  security_realm: jenkins.securityRealm.class.name,
  authorization_strategy: jenkins.authorizationStrategy.class.name,
  controller_config_sha256: sha256(jenkins.getConfigFile().getFile().bytes),
  job_config_sha256: sha256(job.getConfigFile().getFile().bytes),
  principal: [
    user_id: user.id,
    seed: seed
  ],
  decisions: [
    jenkins_read: jenkins.getACL().hasPermission2(authentication, Jenkins.READ),
    item_read: job.getACL().hasPermission2(authentication, Item.READ),
    item_build: job.getACL().hasPermission2(authentication, Item.BUILD),
    item_configure: job.getACL().hasPermission2(authentication, Item.CONFIGURE)
  ]
]
def bytes = JsonOutput.toJson(binding).getBytes(StandardCharsets.UTF_8)
def digest = MessageDigest.getInstance('SHA-256').digest(bytes)
def hex = digest.collect { value -> String.format('%02x', value & 0xff) }.join()
println('SHADOW001_AUTHZ=' + hex)
