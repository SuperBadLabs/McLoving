import hudson.security.AuthorizationStrategy
import hudson.security.SecurityRealm
import jenkins.model.Jenkins

def controller = Jenkins.get()
controller.setSecurityRealm(SecurityRealm.NO_AUTHENTICATION)
controller.setAuthorizationStrategy(AuthorizationStrategy.UNSECURED)
controller.setCrumbIssuer(null)
controller.setNumExecutors(2)
controller.save()

System.setProperty('hudson.plugins.git.GitSCM.ALLOW_LOCAL_CHECKOUT', 'true')
