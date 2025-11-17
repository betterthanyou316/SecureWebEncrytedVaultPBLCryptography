document.addEventListener('DOMContentLoaded', () => {
    console.log("SecureShare WebVault frontend script loaded!");
    // Find the new "Go to Download" form
    const goToDownloadForm = document.getElementById('goToDownloadForm');
    if (goToDownloadForm) {
        // Add an event listener for when the user clicks its "submit" button
        goToDownloadForm.addEventListener('submit', (event) => {
            // Stop the form from submitting in the default way (which would reload the page)
            event.preventDefault();
            // Get the file ID that the user typed into the text box
            const fileId = document.getElementById('fileIdInput').value;       
            if (fileId) {
                // Manually redirect the user's browser to the correct download URL
                // This constructs the URL like: /download/test.jpg.enc
                window.location.href = `/download/${fileId}`;
            }
        });
    }
});