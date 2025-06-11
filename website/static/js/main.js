document.addEventListener('DOMContentLoaded', function() {
    // Plan selection handling
    const planButtons = document.querySelectorAll('[href="#"]');
    const downloadButton = document.getElementById('downloadButton');
    let selectedPlan = null;

    planButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Reset all buttons
            planButtons.forEach(btn => {
                btn.classList.remove('bg-green-600');
                btn.classList.add('bg-blue-600');
                btn.textContent = 'Select Plan';
            });
            
            // Highlight selected plan
            this.classList.remove('bg-blue-600');
            this.classList.add('bg-green-600');
            this.textContent = 'Selected';
            
            // Store selected plan
            selectedPlan = this.closest('.border').querySelector('h2').textContent;
            
            // Update download button
            updateDownloadButton();
        });
    });

    function updateDownloadButton() {
        const button = downloadButton.querySelector('button');
        if (selectedPlan) {
            button.disabled = false;
            button.classList.remove('bg-gray-300', 'text-gray-600');
            button.classList.add('bg-blue-600', 'text-white', 'hover:bg-blue-700');
            button.textContent = 'Download AGIS Defence System';
            
            // Add click handler for download
            button.onclick = initiateDownload;
        } else {
            button.disabled = true;
            button.classList.remove('bg-blue-600', 'text-white', 'hover:bg-blue-700');
            button.classList.add('bg-gray-300', 'text-gray-600');
            button.textContent = 'Select a plan to download';
        }
    }

    function initiateDownload() {
        // Show loading state
        const button = downloadButton.querySelector('button');
        const originalText = button.textContent;
        button.textContent = 'Preparing download...';
        button.disabled = true;

        // Simulate payment process and download
        setTimeout(() => {
            // Reset button state
            button.textContent = originalText;
            button.disabled = false;

            // Create payment form
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/api/payment/process';
            
            // Add plan details
            const planInput = document.createElement('input');
            planInput.type = 'hidden';
            planInput.name = 'plan';
            planInput.value = selectedPlan;
            form.appendChild(planInput);
            
            // Submit form
            document.body.appendChild(form);
            form.submit();
        }, 1500);
    }

    // Smooth scrolling for navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });
}); 