import { match } from "assert";

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
      const codeqlAlerts     = await this.getCodeqlAlerts();
      const existedIssues    = await this.getExistedIssues();

      this.alertDictionary = this.createAlertDictionary(existedIssues);

    //   await this.closeSpoiledIssues();
      await this.createDependabotlIssues(dependabotAlerts);
      await this.createCodeqlIssues(codeqlAlerts);
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
          if (e.message.includes('no analysis found') || e.message.includes('Advanced Security must be enabled for this repository to use code scanning'))
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
          console.log(issue.body.match(/(?<=Repository:\n)[\s\S]*?(?=####|$)/g))
          const [repo] = issue.body.match(/(?<=Repository:\n)[\s\S]*?(?=####|$)/g);
          const [, url, type] = issue.body.match(/Link:\s*(https:.*\/(dependabot|code-scanning)\/(\d+))/);
          const [, cveId] = issue.body.match(/CVE ID:\s*`(.*)`/);;
          const [, ghsaId] = issue.body.match(/GHSA ID:\s*`(.*)`/);;

          if (!url)
              return res;

          res[issue.title] = { issue, type, cveId, ghsaId, repo};

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

  needUpdateIssue (alert) {
    const existIssue = this.alertDictionary[alert.security_advisory.summary]
    return existIssue 
        && existIssue.cveId === alert.security_advisory.cve_id
        && existIssue.ghsaId === alert.security_advisory.ghsa_Id
        && existIssue.repo.search(this.context.repo) === -1;
  }

  async updateIssue (alert) {
    const { issue } = this.alertDictionary[alert.security_advisory.summary]

    const body = issue.body.replace(/(?<=Repository:\n)[\s\S]*?(?=####|$)/g, (match) => {
        return match += `- [ ] \`${this.context.repo}\`\n`;
    });

    return this.github.rest.issues.update({
        owner:        this.context.owner,
        repo:         this.issueRepo,
        issue_number: issue.number,
        body,
    });

  }

  async createDependabotlIssues (dependabotAlerts) {
    for (const alert of dependabotAlerts) {
          if (this.needUpdateIssue(alert)) {
              await this.updateIssue(alert)
              continue
          }

          if (!this.needCreateIssue(alert))
              continue;

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
          }, false);
      }
  }

  needCreateIssue (alert) {
      console.log('alertCheck')
      console.log(!this.alertDictionary[alert.security_advisory.summary])
      console.log(Date.now() - new Date(alert.created_at) <= 1000 * 60 * 60 * 24)
      return !this.alertDictionary[alert.security_advisory.summary];
  }

  async createIssue ({ labels, originRepo, summary, description, link, issuePackage = '', cveId, ghsaId }, isDependabotAlert = true) {
      const title = isDependabotAlert ? `${summary}` : `[${originRepo}] ${summary}`;
      let body = ''
                    + `#### Repository:\n- [ ] \`${originRepo}\`\n`
                    + (issuePackage ? `#### Package: \`${issuePackage}\`\n` : '')
                    + `#### Description:\n`
                    + `${description}\n`
                    + `#### Link: ${link}`;

        if  (isDependabotAlert)
            body += `\n#### CVE ID: \`${cveId}\`\n #### GHSA ID: \`${ghsaId}\``;

      return this.github.rest.issues.create({
          title, body, labels,
          owner: this.context.owner,
          repo:  this.issueRepo,
      });
  }
}

export default SecurityChecker;
