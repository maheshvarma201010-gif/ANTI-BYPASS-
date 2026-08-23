/**
 * Common Shortener Service
 * Integrates Arolinks and VPLinks providers with automatic fallback logic.
 * Ensures API keys are handled server-side and never exposed to clients.
 */

const { shortenWithArolinks } = require('./arolinks');
const { shortenWithVplinks } = require('./vplinks');

/**
 * Shorten a URL using either Arolinks or VPLinks with automatic fallback.
 *
 * @param {string} targetUrl - The long URL to shorten.
 * @param {Object} [options] - Options for shortening.
 * @param {string} [options.primaryProvider] - 'arolinks' or 'vplinks'. Default: 'arolinks'
 * @param {string} [options.arolinksKey] - Override process.env.AROLINKS_API_KEY
 * @param {string} [options.arolinksEndpoint] - Override process.env.AROLINKS_ENDPOINT
 * @param {string} [options.vplinksKey] - Override process.env.VPLINKS_API_KEY
 * @param {string} [options.vplinksEndpoint] - Override process.env.VPLINKS_ENDPOINT
 * @returns {Promise<{shortUrl: string, providerUsed: string}>}
 */
async function shortenUrl(targetUrl, options = {}) {
  const primaryProvider = (options.primaryProvider || process.env.PRIMARY_SHORTENER || 'arolinks').toLowerCase();

  const providers = {
    arolinks: {
      name: 'arolinks',
      fn: (url) => shortenWithArolinks(url, options.arolinksKey || process.env.AROLINKS_API_KEY, options.arolinksEndpoint || process.env.AROLINKS_ENDPOINT)
    },
    vplinks: {
      name: 'vplinks',
      fn: (url) => shortenWithVplinks(url, options.vplinksKey || process.env.VPLINKS_API_KEY, options.vplinksEndpoint || process.env.VPLINKS_ENDPOINT)
    }
  };

  const primary = providers[primaryProvider] || providers.arolinks;
  const secondary = primary.name === 'arolinks' ? providers.vplinks : providers.arolinks;

  // Try primary provider
  try {
    const shortUrl = await primary.fn(targetUrl);
    return { shortUrl, providerUsed: primary.name };
  } catch (primaryError) {
    console.warn(`Primary shortener (${primary.name}) failed: ${primaryError.message}. Attempting fallback to ${secondary.name}...`);
  }

  // Try secondary provider as fallback
  try {
    const shortUrl = await secondary.fn(targetUrl);
    return { shortUrl, providerUsed: secondary.name };
  } catch (secondaryError) {
    throw new Error(`All shortener providers failed. Primary (${primary.name}) and Secondary (${secondary.name}) both failed: ${secondaryError.message}`);
  }
}

module.exports = {
  shortenUrl,
  shortenWithArolinks,
  shortenWithVplinks
};
