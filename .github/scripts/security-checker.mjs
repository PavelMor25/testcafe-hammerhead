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
  
        await this.closeSpoiledIssues();
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
            const [reps] = issue.body.match(/(?<=Repository:)[\s\S]*?(?=####|$)/g);
            const [, url, type, number] = issue.body.match(new RegExp(`\`${this.context.repo}\` - (https:.*/(dependabot|code-scanning)/(\\d+))`));
            const [, cveId] = issue.body.match(/CVE ID:\s*`(.*)`/);
            const [, ghsaId] = issue.body.match(/GHSA ID:\s*`(.*)`/);
  
            if (!url)
                return res;
  
            res.set(issue.title, { issue, type, cveId, ghsaId})
  
            return res;
        }, new Map());
    }
  
    async closeSpoiledIssues () {
        for (const alert of this.alertDictionary.values()) {
  
            if (alert.type === ALERT_TYPES.dependabot) {
                const matchAlertInIssue = alert.issue.body.match(new RegExp(`\`${this.context.repo}\` - (https:.*/(dependabot|code-scanning)/(\\d+))`));
  
                if (!matchAlertInIssue) 
                    continue;
  
                const isAlertOpened = await this.isDependabotAlertOpened(matchAlertInIssue[3]);
  
                if (isAlertOpened)
                    continue;
  
                await this.updateIssue(alert.issue);
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
  
    async updateIssue ({ body, number}) {
        const updatedBody = body.replace(new RegExp(`\\[ \\](?= \`${this.context.repo}\`)`), '[x]');
    
        const allTasksResolved = body.match(/\[ \]/);
    
        return this.github.rest.issues.update({
            owner:        this.context.owner,
            repo:         this.issueRepo,
            issue_number: number,
            state:        !allTasksResolved ? STATES.closed : STATES.open,
            body:         updatedBody,
        });
    }
  
    
    async createDependabotlIssues (dependabotAlerts) {
        for (const alert of dependabotAlerts) {
            if (this.needAddAlertToIssue(alert)) {
                await this.addAlertToIssue(alert);
                continue;
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
  
  needAddAlertToIssue (alert) {
      const existIssue = this.alertDictionary.get(alert.security_advisory.summary);
  
      return existIssue 
          && existIssue.cveId === alert.security_advisory.cve_id
          && existIssue.ghsaId === alert.security_advisory.ghsa_id
          && existIssue.repo.includes(`\`${this.context.repo}\``);
  }
  
  async addAlertToIssue (alert) {
      const { issue } = this.alertDictionary.get(alert.security_advisory.summary);
  
      const body = issue.body.replace(/(?<=Repository:)[\s\S]*?(?=####|$)/g, (match) => {
          return match += `- [ ] \`${this.context.repo}\` - ${alert.html_url}\n`;
      });
  
      return this.github.rest.issues.update({
          owner:        this.context.owner,
          repo:         this.issueRepo,
          issue_number: issue.number,
          body,
      });
  
  }
  
    async createCodeqlIssues (codeqlAlerts) {
        for (const alert of codeqlAlerts) {
            if (!this.needCreateIssue(alert, false))
                continue;
  
            await this.createIssue({
                labels:      [LABELS.codeql, LABELS.security],
                originRepo:  this.context.repo,
                summary:     alert.rule.description,
                description: alert.most_recent_instance.message.text,
                link:        alert.html_url,
            }, false);
        }
    }
  
    needCreateIssue (alert, isDependabotAlert = true) {
        const keyDictionary = isDependabotAlert ? alert.security_advisory.summary : `[${this.context.repo}] ${alert.rule.description}`;
  
        return !this.alertDictionary.get(keyDictionary);
    }
  
    async createIssue ({ labels, originRepo, summary, description, link, issuePackage = '', cveId, ghsaId }, isDependabotAlert = true) {
        const title = isDependabotAlert ? `${summary}` : `[${originRepo}] ${summary}`;
        let body = ''
                      + `#### Repositories:\n`
                      + `- [ ] \`${originRepo}\` - ${link}\n`
                      + (issuePackage ? `#### Package: \`${issuePackage}\`\n` : '')
                      + `#### Description:\n`
                      + `${description}\n`;
  
        if  (isDependabotAlert)
          body += `\n#### CVE ID: \`${cveId}\`\n#### GHSA ID: \`${ghsaId}\``;
    
        return this.github.rest.issues.create({
            title, body, labels,
            owner: this.context.owner,
            repo:  this.issueRepo,
        });
    }
  }
  
  export default SecurityChecker;
  