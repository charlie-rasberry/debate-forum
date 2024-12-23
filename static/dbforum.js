// converts a unix timestamp into a readable date-time format
function convertUnixTimestamp(unixTimestamp) {
    const date = new Date(unixTimestamp * 1000); // unix timestamps are in seconds; eed milliseconds for JS Date
    return date.toLocaleString(); // formats the date into a localized string, e.g., "MM/DD/YYYY, HH:mm:ss"
}

document.addEventListener("DOMContentLoaded", function () {
    // find all elements with the class "timestamp"
    const timestampElements = document.querySelectorAll(".timestamp");

    timestampElements.forEach(element => {
        // grab the unix timestamp from the data-timestamp attribute
        const unixTimestamp = element.getAttribute("data-timestamp");

        // convert it into a readable format and update the element's text
        element.textContent = convertUnixTimestamp(unixTimestamp);
    });
});
