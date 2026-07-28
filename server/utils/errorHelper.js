'use strict';

/**
 * server/utils/errorHelper.js
 * 
 * Shared helper for consistent verification error responses.
 */

/**
 * Sends a canonical verification error response.
 * 
 * @param {object} res - Express response object
 * @param {number} httpStatus - HTTP status code
 * @param {string} code - Machine-readable error code
 * @param {string} message - User-facing error message
 * @param {object} extras - Additional fields to merge into the response
 */
function sendVerificationError(res, httpStatus, code, message, extras = {}) {
    return res.status(httpStatus).json({
        success: false,
        status: 'error',
        code: code,
        message: message,
        ...extras
    });
}

module.exports = {
    sendVerificationError
};
