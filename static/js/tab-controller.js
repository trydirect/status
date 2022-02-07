function displayTab(tabName) {
    let i, content, buttons;

    content = document.getElementsByClassName("tab-content");
    for (i = 0; i < content.length; i++) {
        content[i].style.display = "none";
    }

    buttons = document.getElementsByClassName("tab-button");
    for (i = 0; i < buttons.length; i++) {
        buttons[i].className = buttons[i].className.replace(" active", "");
    }

    document.getElementById(tabName).style.display = "block";
}