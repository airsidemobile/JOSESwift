#!/usr/bin/env groovy
import hudson.FilePath
import hudson.model.Node
import hudson.model.Slave
import jenkins.model.Jenkins
import groovy.time.*

@NonCPS
def findNode(timeout = 600) {
  def pollingInterval = 3 // poll every 3 seconds
  def iterations = timeout / pollingInterval

  // Build up array of nodes
  def Jenkins jenkins = Jenkins.instance
  log("Slave nodes: '$jenkins.nodes'")
  def jenkinsNodes = []
  // No way to break groovy loops, so we have to build up a bigger array
  iterations.times {
    for (Node node in jenkins.nodes) {
      jenkinsNodes << node
    }
  }

  // Pick random fallback node (timeout = max search time)
  def rand = new Random().nextInt(jenkinsNodes.size)
  def Node randomSlave = jenkinsNodes[rand]
  def String theChosenOne = randomSlave.nodeName

  log("If all nodes are busy this Job will be scheduled to run on '$theChosenOne'")
  log("Finding available nodes...")
  jenkinsNodes.find {
    sleep(pollingInterval * 1000) // milliseconds
    if (!isAvailable(it)) return false // try next node
    theChosenOne = it.nodeName
    return true // break; we found an available node
  }

  return theChosenOne
}

@NonCPS
def log(str) {
  Date date = new Date()
  String systemTime = date.format("yyy-mm-dd HH:mm:ss")
  println "[$systemTime] $str"
}

@NonCPS
def isAvailable(Node node) {
  if (!node.getComputer().isOffline()) {
    log("Checking if '$node.nodeName' is busy or not...")
    // Make sure that the slave busy executor number is 0.
    if(node.getComputer().countBusy() == 0) {
      log("'$node.nodeName' seems to have time for us!")
      return true
    } else {
      log("'$node.nodeName' is busy!")
    }
  } else {
    log("'$node.nodeName' is offline!")
  }
  return false
}

@NonCPS
def isJobStartedByUser() {
  def startedByUser = false
  try {
    def buildCauses = currentBuild.rawBuild.getCauses()
    for ( buildCause in buildCauses ) {
      if (buildCause != null) {
        def causeDescription = buildCause.getShortDescription()
        log("Build cause: ${causeDescription}")
        if (causeDescription.contains("Started by user")) {
          startedByUser = true
        }
      }
    }
  } catch(exc) {
    log("Error getting build cause: ${exc}")
    throw exc
  }

  return startedByUser
}

def slave = findNode()

node(slave) {
  withCredentials([[$class: 'StringBinding', credentialsId: '8c157f6e-431b-40dc-969d-edb840552bd5', variable: 'GITHUB_API_TOKEN']]) {

    def scmVars = checkout scm
    def githubStatusJose = { context, status -> githubStatus(GITHUB_API_TOKEN, "jose-ios", scmVars.GIT_COMMIT, context, status) }

    stage('Job Status') {
      log("Job is running on ${slave}")
      if (isJobStartedByUser()) {
        log("Job was started by a user!")
      }
      if (isJobStartedByUser() && env.BRANCH_NAME == 'master') {
        log("...and we are on the master branch! We're gonna make some builds baby! 🎉")
      }
    }

    stage('Install Dependencies') {
      def context = 'jenkins-prepare'
      def cmd = {
        shRVM "bundle install"
        shRVM "bundle exec pod repo update"
      }
      def cmdFinally = {}
      executeCommand(cmd, cmdFinally, githubStatusJose, context)
    }

     stage('SonarQube') {
       // requires SonarQube Scanner 2.8+ to be configured in the build tools section of the jenkins instance
       def scannerHome = tool 'SonarQube Scanner Latest'
       
       if (env.BRANCH_NAME ==~ /^PR-\d+$/) {
         // do the analysis first and do not rely on the built-in scanner
         sh "./run-sonar-swift.sh -nosonarscanner"
         // extract the # without the PR- prefix
         prNo = (env.BRANCH_NAME =~ /^PR-(\d+)$/)[0][1]
         githubToken = env.GITHUB_ACCESS_TOKEN
         // to be configured in the global configuration of the master jenkins instance
         withSonarQubeEnv('SonarQube mohemian Jenkins') {
           sh "${scannerHome}/bin/sonar-scanner -Dsonar.analysis.mode=preview -Dsonar.github.pullRequest=${prNo} -Dsonar.github.oauth=${githubToken}"
         }
      }
      if(env.BRANCH_NAME == 'master') {
        withSonarQubeEnv('SonarQube mohemian Jenkins') {
          // do the analysis first and do not rely on the built-in scanner
           sh "./run-sonar-swift.sh -nosonarscanner"
           sh "${scannerHome}/bin/sonar-scanner"
         }
      }
    }

    stage('Tests') {
      def context = 'jenkins-tests'
      def cmd = {
        shRVM "bundle exec fastlane scan"
      }
      def cmdFinally = {
        publishTestReport()
      }
      executeCommand(cmd, cmdFinally, githubStatusJose, context)
    }
  } // credentials
}

def publishTestReport(title='Test Report') {
  publishHTML([allowMissing: false, alwaysLinkToLastBuild: true, keepAll: true, reportDir: 'test_output/', reportFiles: 'report.html', reportName: title, reportTitles: title])
}

static def executeCommand(command, commandFinally, githubStatusJose, context) {
  githubStatusJose(context, 'pending')
  try {
    command()
  } catch (exc) {
    githubStatusJose(context, 'failure')
    throw exc
  } finally {
    commandFinally()
  }
  githubStatusJose(context, 'success')
}

/**
 * Set the status for a github commit.
 * @param status pending, success, error, failure
 */
def githubStatus(token, repository, sha, context, status) {
  organisation = 'mohemian'

  sh "curl -X POST https://api.github.com/repos/" + organisation + "/" + repository + "/statuses/" + sha + " \\\n" +
          "  -H 'Authorization: token " + token + "' \\\n" +
          "  -H 'cache-control: no-cache' \\\n" +
          "  -H 'content-type: application/json' \\\n" +
          "  -d '{\n" +
          "  \"state\": \"" + status + "\",\n" +
          "  \"context\": \"" + context + "\"\n" +
          "}'"
}

/*
 * Run `sh` with a specific ruby environment, set using RVM, with specific ENV variables and pretty output
 * @param command the command to Run
 * @param version defaults to ruby-2.4.0
 */
def shRVM(command, version="ruby-2.4.0") {
  wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'XTerm', 'defaultFg': 1, 'defaultBg': 2]) {
    withEnv(["PATH+RVM=$HOME/.rvm/bin", 'PATH+LOCALBIN=/usr/local/bin', 'LANG=en_US.UTF-8', 'SNAPSHOT_FORCE_DELETE=1']) {
      sh """\
      #!/bin/bash -l
      echo 'PATH=$PATH'
      echo 'Setting ruby version to ${version} using rvm...'
      source \$(rvm env ${version} --path)
      ${command}
      """
    }
  }
}
