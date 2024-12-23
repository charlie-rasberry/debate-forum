// Function to convert Unix timestamp to a readable date-time format
function convertUnixTimestamp(unixTimestamp) {
    const date = new Date(unixTimestamp * 1000); // Multiply by 1000 to convert seconds to milliseconds
    return date.toLocaleString(); // Returns a locale-specific string (e.g., "MM/DD/YYYY, HH:mm:ss")
}

document.addEventListener("DOMContentLoaded", function () {
    // Find all elements with the class "timestamp"
    const timestampElements = document.querySelectorAll(".timestamp");

    timestampElements.forEach(element => {
        // Get the Unix timestamp from the data attribute
        const unixTimestamp = element.getAttribute("data-timestamp");

        // Convert the timestamp and set the text content
        element.textContent = convertUnixTimestamp(unixTimestamp);
    });
});
