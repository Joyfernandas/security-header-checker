import { Octokit } from "@octokit/rest";

export default async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { url } = req.body;
  
  if (!url || !url.startsWith('http')) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

  try {
    // Trigger workflow
    await octokit.actions.createWorkflowDispatch({
      owner: process.env.GITHUB_OWNER,
      repo: process.env.GITHUB_REPO,
      workflow_id: 'scan.yml',
      ref: 'main',
      inputs: { url }
    });

    // In production, implement webhook/polling for results
    res.status(202).json({ 
      status: 'pending',
      message: 'Scan initiated. Results will be available soon.',
      url
    });
  } catch (error) {
    console.error('GitHub API error:', error);
    res.status(500).json({ 
      error: 'Failed to initiate scan',
      details: error.message 
    });
  }
};