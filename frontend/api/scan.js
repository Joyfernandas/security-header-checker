import { Octokit } from "@octokit/rest";

export default async function handler(req, res) {
  // Set JSON content type immediately
  res.setHeader('Content-Type', 'application/json');
  
  if (req.method !== 'POST') {
    return res.status(405).json({ 
      success: false,
      error: 'Method not allowed' 
    });
  }

  try {
    const { url } = req.body;
    
    if (!url || !url.startsWith('http')) {
      return res.status(400).json({
        success: false,
        error: 'Invalid URL format'
      });
    }

    const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

    // Trigger workflow
    await octokit.actions.createWorkflowDispatch({
      owner: process.env.GITHUB_OWNER,
      repo: process.env.GITHUB_REPO,
      workflow_id: 'scan.yml',
      ref: 'main',
      inputs: { url }
    });

    return res.status(202).json({
      success: true,
      status: 'pending',
      message: 'Scan initiated successfully',
      url
    });

  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message
    });
  }
}