import hudson.security.FullControlOnceLoggedInAuthorizationStrategy
import hudson.security.HudsonPrivateSecurityRealm
import jenkins.model.Jenkins

def controller = Jenkins.get()
def secretFile = new File('/run/secrets/diff003-admin-password')
if (!secretFile.isFile()) {
    throw new IllegalStateException('DIFF-003 bootstrap secret file is missing')
}
def password = secretFile.getText('UTF-8').trim()
if (password.length() < 64) {
    throw new IllegalStateException('DIFF-003 bootstrap secret is too short')
}

def realm = new HudsonPrivateSecurityRealm(false)
realm.createAccount('diff003-admin', password)
controller.setSecurityRealm(realm)
def strategy = new FullControlOnceLoggedInAuthorizationStrategy()
strategy.setAllowAnonymousRead(false)
controller.setAuthorizationStrategy(strategy)
controller.save()
