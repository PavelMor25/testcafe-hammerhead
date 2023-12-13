const STATES = {
  open:   'open',
  closed: 'closed',
};

const LABELS = {
  dependabot: 'dependabot',
  codeq:      'codeql',
  security:   'security notification',
};

const ALERT_TYPES = {
  dependabot: 'dependabot',
  codeq:      'codeql',
}

class SecurityChecker {
  constructor (github, context, issueRepo) {
      this.github    = github;
      this.issueRepo = issueRepo;
      this.context   = {
          owner: context.repo.owner,
          repo:  context.repo.repo,
      };
  }

  async check () {
      const dependabotAlerts = await this.getDependabotAlerts();
    //   const codeqlAlerts     = await this.getCodeqlAlerts();
      const existedIssues    = await this.getExistedIssues();

      this.alertDictionary = this.createAlertDictionary(existedIssues);

    //   await this.closeSpoiledIssues();
      await this.createDependabotlIssues(dependabotAlerts);
    //   await this.createCodeqlIssues(codeqlAlerts);
  }

  async getDependabotAlerts () {
      const { data } = await this.github.rest.dependabot.listAlertsForRepo({ state: STATES.open, ...this.context });

      return data;
  }

  async getCodeqlAlerts () {
      try {
          const { data } = await this.github.rest.codeScanning.listAlertsForRepo({ state: STATES.open, ...this.context });

          return data;
      }
      catch (e) {
          if (e.message.includes('no analysis found'))
              return [];

          throw e;
      }
  }

  async getExistedIssues () {
      const { data: existedIssues } = await this.github.rest.issues.listForRepo({
          owner:  this.context.owner,
          repo:   this.issueRepo,
          labels: [LABELS.security],
          state:  STATES.open,
      });

      return existedIssues;
  }

  createAlertDictionary (existedIssues) {
      return existedIssues.reduce((res, issue) => {
        console.log(issue.body)
        console.log(issue.body.match(/Repository:\s*(.*)(?=\n)/))
          const [, repo] = issue.body.match(/Repository:\s*(.*)(?=\n)/);
          const [, url, type] = issue.body.match(/Link:\s*(https:.*\/(dependabot|code-scanning)\/(\d+))/);
          const [, cveId] = issue.body.match(/CVE ID:\s*`(.*)`/);;
          const [, ghsaIdId] = issue.body.match(/GHSA ID:\s*`(.*)`/);;

          if (!url)
              return res;

          res[issue.title] = { issue, type, cveId, ghsaIdId, repo };

          return res;
      }, {});
  }

  async closeSpoiledIssues () {
      for (const key in this.alertDictionary) {
          const alert = this.alertDictionary[key];

          if (alert.type === ALERT_TYPES.dependabot) {
              const isAlertOpened = await this.isDependabotAlertOpened(alert.number);

              if (isAlertOpened)
                  continue;

              await this.closeIssue(alert.issue.number);
          }
      }
  }

  async isDependabotAlertOpened (alertNumber) {
      const alert = await this.getDependabotAlertInfo(alertNumber);

      return alert.state === STATES.open;
  }

  async getDependabotAlertInfo (alertNumber) {
      try {
          const { data } = await this.github.rest.dependabot.getAlert({ alert_number: alertNumber, ...this.context });

          return data;
      }
      catch (e) {
          if (e.message.includes('No alert found for alert number'))
              return {};

          throw e;
      }
  }

  async closeIssue (issueNumber) {
      return this.github.rest.issues.update({
          owner:        this.context.owner,
          repo:         this.issueRepo,
          issue_number: issueNumber,
          state:        STATES.closed,
      });
  }

  needAddAlertToIssue (alert) {
      const alertDictionaryItem = this.alertDictionary[alert.security_advisory.summary];

      return alertDictionaryItem 
        && alertDictionaryItem.ghsaId === alert.security_advisory.ghsa_id
        && alertDictionaryItem.cveId === alert.security_advisory.cve_id;
  }

  async AddAlertToIssue (alert) {
      const issueInfo = this.alertDictionary[alert.security_advisory.summary];

      if (issueInfo.repo.search(this.context.repo) === -1)
        return;

      const newBody = issueInfo.issue.body.replace(/(?<=Repository:\s).*(?=\n)/gm, (repo) => {
        return repo + `, ${this.context.repo}`
      })
      
      return this.github.rest.issues.update({
        owner:        this.context.owner,
        repo:         this.issueRepo,
        issue_number: issueInfo.issue.issueNumber,
        body:         newBody,
    });
  }


  async createDependabotlIssues (dependabotAlerts) {
    for (const alert of dependabotAlerts) {
            console.log(this.needCreateIssue(alert))
            console.log(this.needAddAlertToIssue(alert))
          if (!this.needCreateIssue(alert))
              return;

          if (this.needAddAlertToIssue(alert))
              await this.AddAlertToIssue(alert);
          else {
              await this.createIssue({
                  labels:       [LABELS.dependabot, LABELS.security, alert.dependency.scope],
                  originRepo:   this.context.repo,
                  summary:      alert.security_advisory.summary,
                  description:  alert.security_advisory.description,
                  link:         alert.html_url,
                  issuePackage: alert.dependency.package.name,
                  cveId:        alert.security_advisory.cve_id,
                  ghsaId:       alert.security_advisory.ghsa_id,
              });
          }
      }
  }

  async createCodeqlIssues (codeqlAlerts) {
      for (const alert of codeqlAlerts) {
          if (!this.needCreateIssue(alert))
              return;

          await this.createIssue({
              labels:      [LABELS.codeql, LABELS.security],
              originRepo:  this.context.repo,
              summary:     alert.rule.description,
              description: alert.most_recent_instance.message.text,
              link:        alert.html_url,
          });
      }
  }

  needCreateIssue (alert) {
      return !this.alertDictionary[alert.security_advisory.summary] && Date.now() - new Date(alert.created_at) <= 1000 * 60 * 60 * 24;
  }

  async createIssue ({ labels, originRepo, summary, description, link, issuePackage = '', cveId, ghsaId }) {
      const title = `${summary}`;
      const body = ''
                    + `#### Repository: \`${originRepo}\`\n`
                    + (issuePackage ? `#### Package: \`${issuePackage}\`\n` : '')
                    + `#### Description:\n`
                    + `${description}\n`
                    + `#### Link: ${link}\n`
                    + `#### CVE ID: \`${cveId}\`\n`
                    + `#### GHSA ID: \`${ghsaId}\``;

      return this.github.rest.issues.create({
          title, body, labels,
          owner: this.context.owner,
          repo:  this.issueRepo,
      });
  }
}

export default SecurityChecker;
