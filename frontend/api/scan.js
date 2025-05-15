import { Octokit } from "@octokit/rest";

export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Set JSON content type
  res.setHeader('Content-Type', 'application/json');

  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ 
        success: false,
        error: 'Method not allowed' 
      });
    }

    const { url } = req.body;
    
    if (!url) {
      return res.status(400).json({
        success: false,
        error: 'URL is required'
      });
    }

    // Validate URL format
    try {
      new URL(url);
    } catch (e) {
      return res.status(400).json({
        success: false,
        error: 'Invalid URL format'
      });
    }

    // Trigger GitHub Actions
    const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
    
    await octokit.rest.actions.createWorkflowDispatch({
      owner: process.env.GITHUB_OWNER,
      repo: process.env.GITHUB_REPO,
      workflow_id: 'scan.yml',
      ref: 'main',
      inputs: { url }
    });

    return res.json({
      success: true,
      message: 'Scan initiated',
      url: url
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