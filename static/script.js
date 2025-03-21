/**
 * Pharmacy Exam Prep - Main script file
 * Contains all the frontend functionality for the application
 */

// Initialize on document load
document.addEventListener('DOMContentLoaded', function() {
    setupSocketConnection();
    enhanceUI();
    setupQuizTimer();
    setupFormAnimations();
    addTooltips();
    enhanceResultsPage();
    setupDropdowns();
    setupFlashMessages();
    setupCSRFProtection();
    setupExportButtons();
    addTableExport();
    makeTablesResponsive();
});

/**
 * Set up Socket.IO connection for real-time updates
 */
function setupSocketConnection() {
    // Only connect to socket if we're on admin pages
    if (document.getElementById('updates-list') || document.getElementById('active-users')) {
        try {
            const socket = io('/admin', {
                reconnection: true,
                reconnectionAttempts: 5,
                reconnectionDelay: 1000,
                reconnectionDelayMax: 5000
            });
            
            socket.on('connect_error', (error) => {
                console.error('Socket connection failed:', error);
            });
            
            socket.on('active_users', (data) => {
                const activeUsers = document.getElementById('active-users');
                if (activeUsers) {
                    activeUsers.textContent = data.count;
                    activeUsers.classList.add('bounce');
                    setTimeout(() => activeUsers.classList.remove('bounce'), 500);
                }
            });
            
            socket.on('new_question', (data) => addUpdate(`New question: ${data.question}`));
            socket.on('new_result', (data) => addUpdate(`${data.username} scored ${data.score} in ${data.time_taken}s`));
            socket.on('new_review', (data) => addUpdate(`${data.username} rated Q${data.question_id}: ${data.rating}/5`));
        } catch (error) {
            console.error('Error setting up socket connection:', error);
        }
    }
}

/**
 * Add an update to the updates list
 */
function addUpdate(message) {
    const list = document.getElementById('updates-list');
    if (!list) return;
    
    const li = document.createElement('li');
    li.textContent = `${new Date().toLocaleTimeString()} - ${message}`;
    li.classList.add(
        'animate-slide-up', 
        'bg-gradient-to-r', 
        'from-blue-50', 
        'to-gray-50', 
        'dark:from-indigo-900', 
        'dark:to-gray-800', 
        'rounded-md', 
        'p-2', 
        'shadow-sm'
    );
    
    list.prepend(li);
    setTimeout(() => li.classList.add('opacity-100'), 10);
    
    // Limit list to 10 items
    if (list.children.length > 10) {
        list.removeChild(list.lastChild);
    }
}

/**
 * Set up the quiz timer
 */
function setupQuizTimer() {
    const timerElement = document.getElementById('timer');
    if (!timerElement) return;
    
    let startTime = new Date();
    timerElement.classList.remove('hidden');
    
    const interval = setInterval(() => {
        let now = new Date();
        let diff = Math.floor((now - startTime) / 1000);
        let minutes = Math.floor(diff / 60).toString().padStart(2, '0');
        let seconds = (diff % 60).toString().padStart(2, '0');
        
        timerElement.textContent = `Time: ${minutes}:${seconds}`;
        timerElement.dataset.time = diff;
        timerElement.classList.add('pulse');
        setTimeout(() => timerElement.classList.remove('pulse'), 200);
    }, 1000);
    
    const quizForm = document.querySelector('.quiz-form');
    if (quizForm) {
        quizForm.addEventListener('submit', () => {
            clearInterval(interval);
            const hiddenInput = document.createElement('input');
            hiddenInput.type = 'hidden';
            hiddenInput.name = 'time_taken';
            hiddenInput.value = timerElement.dataset.time || 0;
            quizForm.appendChild(hiddenInput);
        });
    }
}

/**
 * Add animations to forms
 */
function setupFormAnimations() {
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', () => {
            form.classList.add('animate-scale-up');
            setTimeout(() => form.classList.remove('animate-scale-up'), 300);
        });
        
        form.querySelectorAll('input, textarea, select').forEach(input => {
            input.addEventListener('focus', () => {
                input.classList.add('ring-2', 'ring-indigo-300', 'shadow-lg', 'dark:ring-indigo-500');
            });
            
            input.addEventListener('blur', () => {
                input.classList.remove('ring-2', 'ring-indigo-300', 'shadow-lg', 'dark:ring-indigo-500');
            });
        });
    });
}

/**
 * Add tooltips to elements with data-tooltip attribute
 */
function addTooltips() {
    document.querySelectorAll('[data-tooltip]').forEach(el => {
        el.addEventListener('mouseenter', () => {
            const tooltip = document.createElement('div');
            tooltip.textContent = el.dataset.tooltip;
            tooltip.classList.add(
                'tooltip', 
                'absolute', 
                'bg-gray-800', 
                'text-white', 
                'p-2', 
                'rounded-md', 
                'text-sm', 
                'shadow-lg', 
                'dark:bg-gray-900', 
                'z-50'
            );
            
            document.body.appendChild(tooltip);
            
            const rect = el.getBoundingClientRect();
            tooltip.style.top = `${rect.top - tooltip.offsetHeight - 10 + window.scrollY}px`;
            tooltip.style.left = `${rect.left + rect.width / 2}px`;
            tooltip.style.transform = 'translateX(-50%)';
            
            // Add fadeIn animation
            tooltip.style.opacity = '0';
            setTimeout(() => tooltip.style.opacity = '1', 10);
        });
        
        el.addEventListener('mouseleave', () => {
            const tooltip = document.querySelector('.tooltip');
            if (tooltip) {
                tooltip.style.opacity = '0';
                setTimeout(() => tooltip.remove(), 200);
            }
        });
    });
}

/**
 * Enhance results page
 */
function enhanceResultsPage() {
    // Make questions expandable/collapsible
    document.querySelectorAll('.question').forEach(question => {
        question.addEventListener('click', (e) => {
            // Don't toggle if user is clicking on input, button, etc.
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || 
                e.target.tagName === 'BUTTON' || e.target.tagName === 'A' ||
                e.target.closest('form')) return;
                
            const details = question.querySelector('.question-details');
            if (details) {
                details.classList.toggle('hidden');
                question.classList.toggle('expanded');
                
                // Change icon rotation if exists
                const expandIcon = question.querySelector('.expand-icon');
                if (expandIcon) {
                    expandIcon.style.transform = details.classList.contains('hidden') ? '' : 'rotate(180deg)';
                }
                
                // Scroll into view if expanding and not already visible
                if (!details.classList.contains('hidden')) {
                    setTimeout(() => {
                        if (!isElementInViewport(details)) {
                            details.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                        }
                    }, 100);
                }
            }
        });
    });
    
    // Add rating previews
    document.querySelectorAll('.review-form select').forEach(select => {
        select.addEventListener('change', (e) => {
            const rating = e.target.value;
            const preview = select.parentElement.querySelector('.rating-preview') || document.createElement('span');
            
            preview.classList.add(
                'rating-preview', 
                'text-sm', 
                'ml-2', 
                'inline-block',
                'transition-all',
                'duration-300'
            );
            
            // Add star rating visualization
            if (rating) {
                const starCount = parseInt(rating);
                let stars = '';
                for (let i = 0; i < 5; i++) {
                    stars += i < starCount 
                        ? '<span class="text-yellow-500">★</span>' 
                        : '<span class="text-gray-400">☆</span>';
                }
                preview.innerHTML = stars;
            } else {
                preview.textContent = '';
            }
            
            if (!select.parentElement.querySelector('.rating-preview')) {
                select.parentElement.appendChild(preview);
            }
        });
    });
    
    // Add animation to confetti (if score is high)
    const confettiContainer = document.querySelector('.confetti');
    if (confettiContainer) {
        for (let i = 0; i < 50; i++) {
            const confetti = document.createElement('div');
            
            // Random colors
            const colors = ['bg-indigo-500', 'bg-purple-500', 'bg-pink-500', 'bg-blue-500', 'bg-green-500', 'bg-yellow-500'];
            const randomColor = colors[Math.floor(Math.random() * colors.length)];
            
            // Random sizes
            const size = Math.random() * 10 + 5;
            
            confetti.classList.add(
                'absolute', 
                'rounded-full', 
                'animate-confetti',
                randomColor
            );
            
            confetti.style.width = `${size}px`;
            confetti.style.height = `${size}px`;
            confetti.style.left = `${Math.random() * 100}%`;
            confetti.style.top = '0';
            confetti.style.animationDelay = `${Math.random() * 2}s`;
            confetti.style.animationDuration = `${Math.random() * 3 + 2}s`;
            
            confettiContainer.appendChild(confetti);
        }
    }
}

/**
 * Set up dropdown menus
 */
function setupDropdowns() {
    document.querySelectorAll('.dropdown').forEach(dropdown => {
        const button = dropdown.querySelector('button');
        const menu = dropdown.querySelector('.dropdown-menu');
        
        if (!button || !menu) return;
        
        button.addEventListener('click', (e) => {
            e.stopPropagation();
            menu.classList.toggle('hidden');
        });
        
        // Close dropdown when clicking outside
        document.addEventListener('click', () => {
            menu.classList.add('hidden');
        });
        
        // Prevent clicks inside dropdown from closing it
        menu.addEventListener('click', (e) => {
            e.stopPropagation();
        });
    });
}

/**
 * Set up flash messages auto-dismiss
 */
function setupFlashMessages() {
    document.querySelectorAll('.flash').forEach(flash => {
        // Add auto-dismiss after 5 seconds
        setTimeout(() => {
            flash.style.opacity = '0';
            setTimeout(() => flash.remove(), 500);
        }, 5000);
        
        // Add close button functionality
        const closeBtn = flash.querySelector('.close-flash');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                flash.style.opacity = '0';
                setTimeout(() => flash.remove(), 500);
            });
        }
    });
}

/**
 * Add CSRF protection to all forms
 */
function setupCSRFProtection() {
    // Get CSRF token from meta tag
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
    
    if (csrfToken) {
        // Add token to all forms
        document.querySelectorAll('form').forEach(form => {
            // Skip if form already has CSRF token
            if (form.querySelector('input[name="csrf_token"]')) return;
            
            const csrfInput = document.createElement('input');
            csrfInput.type = 'hidden';
            csrfInput.name = 'csrf_token';
            csrfInput.value = csrfToken;
            form.appendChild(csrfInput);
        });
        
        // Add token to AJAX requests
        const originalXhrOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function() {
            originalXhrOpen.apply(this, arguments);
            this.setRequestHeader('X-CSRF-Token', csrfToken);
        };
    }
}

/**
 * General UI enhancements
 */
function enhanceUI() {
    // Add active class to current page link in navigation
    const currentLocation = window.location.pathname;
    document.querySelectorAll('nav a').forEach(link => {
        if (link.getAttribute('href') === currentLocation) {
            link.classList.add('bg-blue-500', 'dark:bg-blue-600', 'rounded-lg');
        }
    });
    
    // Add dark mode toggle
    const header = document.querySelector('nav .container');
    if (header) {
        const darkModeToggle = document.createElement('button');
        darkModeToggle.classList.add(
            'flex', 'items-center', 'justify-center', 
            'w-8', 'h-8', 'rounded-full', 
            'bg-gray-700', 'dark:bg-gray-200', 
            'text-gray-200', 'dark:text-gray-700',
            'transition-colors', 'duration-200'
        );
        
        // Add icon based on current theme
        darkModeToggle.innerHTML = document.documentElement.classList.contains('dark') 
            ? '<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clip-rule="evenodd" /></svg>'
            : '<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor"><path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" /></svg>';
        
        darkModeToggle.addEventListener('click', toggleDarkMode);
        
        header.appendChild(darkModeToggle);
    }
}

/**
 * Toggle dark mode
 */
function toggleDarkMode() {
    const isDarkMode = document.documentElement.classList.toggle('dark');
    localStorage.setItem('darkMode', isDarkMode);
    
    // Update toggle icon
    const toggle = document.querySelector('nav button');
    if (toggle) {
        toggle.innerHTML = isDarkMode
            ? '<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clip-rule="evenodd" /></svg>'
            : '<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor"><path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" /></svg>';
    }
}

/**
 * Check if element is in viewport
 */
function isElementInViewport(el) {
    const rect = el.getBoundingClientRect();
    
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}

/**
 * Set up export buttons
 */
function setupExportButtons() {
    document.querySelectorAll('.export-button').forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const exportMenu = this.nextElementSibling;
            exportMenu.classList.toggle('hidden');
            
            // Close when clicking elsewhere
            document.addEventListener('click', function closeMenu(event) {
                if (!exportMenu.contains(event.target) && !button.contains(event.target)) {
                    exportMenu.classList.add('hidden');
                    document.removeEventListener('click', closeMenu);
                }
            });
        });
    });
}

/**
 * Add export functionality to all tables
 */
function addTableExport() {
    document.querySelectorAll('.data-table').forEach(table => {
        const tableId = table.id || 'data-table';
        const container = table.parentElement;
        
        // Create export button and dropdown
        const exportContainer = document.createElement('div');
        exportContainer.className = 'export-container relative mb-4 mt-2 flex justify-end';
        exportContainer.innerHTML = `
            <button class="export-button btn-secondary flex items-center px-3 py-2 text-sm">
                <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                Export
            </button>
            <div class="export-menu hidden absolute right-0 mt-10 py-2 w-48 bg-white dark:bg-gray-700 rounded-md shadow-xl z-10">
                <a href="#" class="export-csv block px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-600">
                    Export as CSV
                </a>
                <a href="#" class="export-pdf block px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-600">
                    Export as PDF
                </a>
            </div>
        `;
        
        // Insert before the table
        if (container.firstChild) {
            container.insertBefore(exportContainer, container.firstChild);
        } else {
            container.appendChild(exportContainer);
        }
        
        // Add event listeners to export links
        exportContainer.querySelector('.export-csv').addEventListener('click', function(e) {
            e.preventDefault();
            exportTableToCSV(table, tableId + '.csv');
        });
        
        exportContainer.querySelector('.export-pdf').addEventListener('click', function(e) {
            e.preventDefault();
            exportTableToPDF(table, tableId + '.pdf');
        });
    });
    
    // Initialize export buttons
    setupExportButtons();
}

/**
 * Export table to CSV
 */
function exportTableToCSV(table, filename) {
    const rows = table.querySelectorAll('tr');
    let csv = [];
    
    for (let i = 0; i < rows.length; i++) {
        const row = [], cols = rows[i].querySelectorAll('td, th');
        
        for (let j = 0; j < cols.length; j++) {
            // Replace any commas in the cell text to avoid CSV issues
            let text = cols[j].innerText.replace(/,/g, ' ');
            // Remove multiple spaces and trim
            text = text.replace(/\s+/g, ' ').trim();
            // Wrap in quotes
            row.push('"' + text + '"');
        }
        
        csv.push(row.join(','));
    }
    
    // Download CSV file
    downloadFile(csv.join('\n'), filename, 'text/csv');
}

/**
 * Export table to PDF
 */
function exportTableToPDF(table, filename) {
    // Alert that we're redirecting them to a proper print view
    alert('Please use the browser print dialog to save as PDF');
    
    // Create a printable version
    const printWindow = window.open('', '_blank');
    
    // Get table data
    const rows = table.querySelectorAll('tr');
    let tableHTML = '<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%;">';
    
    for (let i = 0; i < rows.length; i++) {
        const cols = rows[i].querySelectorAll('td, th');
        
        tableHTML += '<tr>';
        for (let j = 0; j < cols.length; j++) {
            const isHeader = cols[j].tagName === 'TH';
            const style = isHeader ? 'background-color: #f3f4f6; font-weight: bold;' : '';
            tableHTML += `<${isHeader ? 'th' : 'td'} style="${style}">${cols[j].innerText}</${isHeader ? 'th' : 'td'}>`;
        }
        tableHTML += '</tr>';
    }
    
    tableHTML += '</table>';
    
    // Generate the printable page
    printWindow.document.write(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>${filename}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #333; margin-bottom: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
                th { background-color: #f3f4f6; }
                @media print {
                    .no-print { display: none; }
                    body { margin: 0; }
                }
            </style>
        </head>
        <body>
            <div class="no-print" style="margin-bottom: 20px;">
                <h1>${filename.replace('.pdf', '')}</h1>
                <button onclick="window.print();" style="padding: 8px 16px; background: #4f46e5; color: white; border: none; border-radius: 4px; cursor: pointer;">Print/Save as PDF</button>
            </div>
            ${tableHTML}
        </body>
        </html>
    `);
    
    printWindow.document.close();
}

/**
 * Helper function to download file
 */
function downloadFile(content, filename, contentType) {
    const a = document.createElement('a');
    const file = new Blob([content], { type: contentType });
    
    a.href = URL.createObjectURL(file);
    a.download = filename;
    a.click();
    
    URL.revokeObjectURL(a.href);
}

/**
 * Make tables responsive on mobile
 */
function makeTablesResponsive() {
    const tables = document.querySelectorAll('table:not(.responsive)');
    tables.forEach(table => {
        table.classList.add('responsive');
        
        // Only add wrapper if not already in one
        if (!table.parentElement.classList.contains('overflow-x-auto')) {
            const wrapper = document.createElement('div');
            wrapper.className = 'overflow-x-auto';
            table.parentNode.insertBefore(wrapper, table);
            wrapper.appendChild(table);
        }
    });
}

/**
 * Globally accessible export functions that can be called from any page
 */
window.exportTools = {
    exportTableToCSV: function(tableId, filename) {
        const table = document.getElementById(tableId);
        if (table) exportTableToCSV(table, filename);
    },
    
    exportToPDF: function(elementId) {
        const element = document.getElementById(elementId);
        if (element) exportTableToPDF(element, elementId + '.pdf');
    }
};