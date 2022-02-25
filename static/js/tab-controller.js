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

function checkOnUpdate(url){
    var xhr = new XMLHttpRequest();
    xhr.open("GET", url);

    xhr.setRequestHeader("Accept", "*/*");
      xhr.onreadystatechange = function () {
          if (xhr.readyState === 4) {
              let r = JSON.parse(xhr.responseText);
              if (r["upd"] === true) {
                  document.getElementById('update_crd').style.display = 'block';
                  document.getElementById('notifyCounter').removeAttribute('hidden');
              }
          }
      };
    xhr.send();
    setInterval(() => checkOnUpdate(url), 200000);
}