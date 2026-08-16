import jenkins.model.Jenkins

def shell = Jenkins.get().getDescriptorByType(hudson.tasks.Shell.DescriptorImpl.class)
shell.setShell('/var/jenkins_home/mig005a-nonexecuting-shell')
shell.save()
