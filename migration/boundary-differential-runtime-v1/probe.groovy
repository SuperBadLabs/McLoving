import groovy.json.JsonOutput
import hudson.model.Job
import jenkins.model.Jenkins

def controller = Jenkins.get()
def triggerClasses = [
    'hudson.triggers.SCMTrigger',
    'hudson.triggers.TimerTrigger'
]
def loadedTriggers = triggerClasses.findAll { name ->
    try {
        controller.pluginManager.uberClassLoader.loadClass(name)
        return true
    } catch (ClassNotFoundException ignored) {
        return false
    }
}

def observation = [
    schema: 'mcloving.diff003.jenkins-runtime/v1',
    controller_version: Jenkins.VERSION,
    security_realm: controller.securityRealm.class.name,
    authorization_strategy: controller.authorizationStrategy.class.name,
    loaded_trigger_classes: loadedTriggers,
    jobs: controller.getAllItems(Job.class).size(),
    production_boundary_mappings: 0,
    external_effects: 0,
    production_credentials: false,
    production_endpoints: [],
    authenticated_operator: 'diff003-admin'
]
println('DIFF003=' + JsonOutput.toJson(observation))
