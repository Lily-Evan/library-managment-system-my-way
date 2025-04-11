/**
 * Library Management System - Main JavaScript
 */

// Helper function to get cookie value
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

// Function to format date to locale string
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString();
}

// Check if element is in viewport (for lazy loading)
function isInViewport(element) {
    const rect = element.getBoundingClientRect();
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}

// Add error handler for fetch operations
function handleFetchError(error) {
    console.error('API Error:', error);
    return { error: error.message || 'An unknown error occurred' };
}

// Generic function to make API calls
async function apiCall(endpoint, options = {}) {
    try {
        const accessToken = getCookie('access_token');
        
        // Set default headers
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };
        
        // Add authorization header if token exists
        if (accessToken) {
            headers['Authorization'] = `Bearer ${accessToken}`;
        }
        
        const response = await fetch(endpoint, {
            ...options,
            headers
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.msg || `API error: ${response.status}`);
        }
        
        return data;
    } catch (error) {
        return handleFetchError(error);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Check authentication state and update UI
    updateAuthState();
    
    // Add any global event listeners here
});

// Update UI based on authentication state
function updateAuthState() {
    const accessToken = getCookie('access_token');
    const isAdmin = getCookie('is_admin') === 'True';
    
    if (accessToken) {
        // User is authenticated
        document.querySelectorAll('.user-authenticated').forEach(el => el.classList.remove('d-none'));
        document.querySelectorAll('.user-unauthenticated').forEach(el => el.classList.add('d-none'));
        
        // Show admin sections if applicable
        if (isAdmin) {
            document.querySelectorAll('.admin-only').forEach(el => el.classList.remove('d-none'));
        } else {
            document.querySelectorAll('.admin-only').forEach(el => el.classList.add('d-none'));
        }
    } else {
        // User is not authenticated
        document.querySelectorAll('.user-authenticated').forEach(el => el.classList.add('d-none'));
        document.querySelectorAll('.user-unauthenticated').forEach(el => el.classList.remove('d-none'));
        document.querySelectorAll('.admin-only').forEach(el => el.classList.add('d-none'));
    }
}
