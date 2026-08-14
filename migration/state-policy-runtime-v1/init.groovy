import hudson.security.FullControlOnceLoggedInAuthorizationStrategy
import hudson.security.HudsonPrivateSecurityRealm
import jenkins.model.Jenkins

def jenkins = Jenkins.get()
def fixturePassword = System.getenv('DIFF002_ADMIN_PASSWORD')
if (fixturePassword == null || fixturePassword.isEmpty()) {
  throw new IllegalStateException('DIFF002_ADMIN_PASSWORD is required')
}
def realm = new HudsonPrivateSecurityRealm(false)
realm.createAccount('diff002-admin', fixturePassword)
realm.createAccount('jenkins-user-immutable-1042', fixturePassword)
realm.createAccount('jenkins-user-deleted-reuse-2042', fixturePassword)
jenkins.securityRealm = realm
jenkins.authorizationStrategy = new FullControlOnceLoggedInAuthorizationStrategy(false)
jenkins.save()
println('diff002_runtime_fixture_ready')
