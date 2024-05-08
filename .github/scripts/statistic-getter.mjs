const STATES = {
    open:   'open',
    closed: 'closed',
};

const FORKED = [
    'bin-v8-flags-filter',
    'callsite-record',
    'error-stack-parser'
]

class StatisticGetter {
    constructor(github, context, issueRepo) {
        this.github    = github;
        this.issueRepo = issueRepo;
        this.context   = {
            owner: context.repo.owner,
            repo:  context.repo.repo,
        };
    }

    async getStats () {
        const alerts    = await this.getDependabotAlertsLength();
        const issues    = await this.getExistedIssuesLength();
        const downloads = await this.getDownloads();
        const statIssue = await this.getStatIssue();

        if (!statIssue)
            return await this.createStatIssue(issues, alerts, downloads);

        if (!statIssue.body.includes(`|${this.context.repo}|`))
            return await this.addRepoToStat(statIssue, issues, alerts, downloads);

        // await this.updatePackageStat(statIssue, issues, alerts, downloads);

    }

    async getDependabotAlertsLength () {
        const { data } = await this.github.rest.dependabot.listAlertsForRepo({ state: STATES.open, ...this.context });

        return data.length;
    }

    async getExistedIssuesLength () {
        const { data: existedIssues } = await this.github.rest.issues.listForRepo({
            owner:  this.context.owner,
            repo:   this.issueRepo,
            state:  STATES.open,
        });

        return existedIssues.length;
    }

    async getDownloads () {
        const repo = FORKED.includes(this.context.repo) 
            ? '@devexpress/' + this.context.repo
            : this.context.repo

        const req  = await fetch(`https://api.npmjs.org/downloads/point/last-month/${repo}`);
        const info = await req.json();
        
        return info.downloads || 0;
    }

    async getStatIssue () {
        const { data: existedIssues } = await this.github.rest.issues.listForRepo({
            owner:  this.context.owner,
            repo:   this.issueRepo,
            state:  STATES.open,
        });

        return existedIssues.find(({ title }) => title.includes(`TestCafe's repositories statistic`))
    }

    async addRepoToStat ({number, body}, issues, alerts, downloads) {
        const updates = {};

        updates.issue_number = number;
        updates.body         = body + `|${this.context.repo}|${downloads}|${issues}|${alerts}|\n`;

        await this.updateIssue(updates)
    }

    // async updatePackageStat ({number, body}, issues, alerts, downloads) {

    // }


    async updateIssue (updates) {
        return this.github.rest.issues.update({
            owner: this.context.owner,
            repo:  this.issueRepo,
            ...updates,
        });
    }

    async createStatIssue (issues, alerts, downloads) {
        const title = `TestCafe's repositories statistic on ${this.getDate()}`;
        const body  = ''
            + `|Package name|Downloads|Issues|alerts|\n`
            + `|--------|--------|--------|--------|\n`
            + `|${this.context.repo}|${downloads}|${issues}|${alerts}|\n`

        return this.github.rest.issues.create({
            title, body,
            owner: this.context.owner,
            repo:  this.issueRepo,
        });
    }

    getDate () {
        const date  = new Date();
        const day   = `${date.getDate()}`.padStart(2, "0");
        const month = `${date.getMonth() + 1}`.padStart(2, "0");

        return `${day}.${month}.${date.getFullYear()}`;
    }
}

export default StatisticGetter