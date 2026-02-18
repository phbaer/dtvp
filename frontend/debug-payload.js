// Quick debug script to test team details payload
// Run this in browser console while testing

// Intercept updateAssessment calls
const originalFetch = window.fetch;
window.fetch = function (...args) {
    if (args[0]?.includes('/api/assessment')) {
        console.log('=== ASSESSMENT PAYLOAD ===');
        console.log('URL:', args[0]);
        if (args[1]?.body) {
            try {
                const body = JSON.parse(args[1].body);
                console.log('Team:', body.team);
                console.log('State:', body.state);
                console.log('Details:', body.details);
                console.log('Full payload:', body);
            } catch (e) {
                console.log('Body:', args[1].body);
            }
        }
        console.log('========================');
    }
    return originalFetch.apply(this, args);
};

console.log('✅ Fetch interceptor installed. Team assessment payloads will be logged.');
