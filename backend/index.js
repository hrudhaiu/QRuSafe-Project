const express = require('express');
const axios = require('axios');
const cors = require('cors'); // Import CORS package
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 234;

app.use(cors()); // Enable CORS for all requests
app.use(express.json());

// Endpoint to check URL safety using Google Safe Browsing API
app.post('/api/check-url', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  try {
    const requestBody = {
      client: {
        clientId: "QRuSafe",
        clientVersion: "1.0"
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };

    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_API_KEY}`,
      requestBody
    );

    // If no threat matches, the response will be empty
    if (response.data && Object.keys(response.data).length === 0) {
      return res.json({ safe: true, details: "URL appears safe." });
    } else {
      return res.json({ safe: false, details: response.data });
    }
  } catch (error) {
    console.error("Error checking URL:", error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});