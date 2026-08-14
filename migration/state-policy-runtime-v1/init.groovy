import hudson.security.FullControlOnceLoggedInAuthorizationStrategy
import hudson.security.HudsonPrivateSecurityRealm
import jenkins.model.Jenkins

def jenkins = Jenkins.get()
def fixturePassword = new File('/run/secrets/diff002-admin-password').text.trim()
if (fixturePassword == null || fixturePassword.isEmpty()) {
  throw new IllegalStateException('the DIFF-002 runtime password file is empty')
}
def realm = new HudsonPrivateSecurityRealm(false)
realm.createAccount('diff002-admin', fixturePassword)
realm.createAccount('jenkins-user-immutable-1042', fixturePassword)
realm.createAccount('alice-reused', fixturePassword)
jenkins.securityRealm = realm
def strategy = new FullControlOnceLoggedInAuthorizationStrategy()
strategy.setAllowAnonymousRead(false)
jenkins.authorizationStrategy = strategy
jenkins.save()
println('diff002_runtime_fixture_ready')
