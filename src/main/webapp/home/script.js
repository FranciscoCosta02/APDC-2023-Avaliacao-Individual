function showToken(){
    const url = '/rest/show';
    fetch(url, {
        method: 'GET',
        headers:{
            'Authorization':'Bearer ' + localStorage.getItem("token")
        }
    })
    .then(response => response.json())
    .then (data =>{
        var properties = data.properties;
        console.log(JSON.stringify(properties));
        alert("Token: " + localStorage.getItem("token") + "\nUsername: " + properties.username.value + 
        "\nCreation Date: " + properties.creation_date.value + "\nExpiration Date: " + properties.expiration_date.value);
    })
    .catch(error => {console.log(error)});
}

function removeFromLocalStorage() {
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    localStorage.removeItem("role");
}

function deleteUser() {
    if(localStorage.getItem("role") == "User") {
        const url = '/rest/delete';
        fetch(url + "/" + username, {
            method: 'DELETE',
            headers:{
                'Authorization':'Bearer ' + localStorage.getItem("token"),
            }
        })
        .then (response => {
            if(response.ok) {
                removeFromLocalStorage()
                window.location.href = "./../index.html";
            } else {
                alert("Error")
            }   
        })
    } else {
        window.location.href = "./deleteUser.html";
    }
}

function deleteOther() {
    event.preventDefault();
    const url = '/rest/delete';
    const username = document.getElementById('username').value;
    fetch(url + "/" + username, {
        method: 'DELETE',
        headers:{
            'Authorization':'Bearer ' + localStorage.getItem("token"),
        }
    })
    .then (response => {
        if(response.ok) {
            if(username == localStorage.getItem('username')) {
                removeFromLocalStorage();
                window.location.href = "./../index.html";
            } else {
                alert("User deleted");
                GoToCorrectHome();
            }
        } else {
            alert("Error");
        }     
    })
}

function logout() {
    const url = '/rest/logout';
    fetch(url, {
        method: 'DELETE',
        headers:{
            'Authorization':'Bearer ' + localStorage.getItem("token")
        }
    })
    .then (response => {
        if(response.ok) {
            removeFromLocalStorage()
            window.location.href = "./../index.html";
        } else {
            alert("Error")
        }
    })
}

function GoToUpdate() {
    if(localStorage.getItem("role") == "User") {
        alert("No permissions!");
    } else {
        window.location.href = "./updateOther.html";
    }
}

function GoToUpdatePWD() {
    window.location.href = "./updatePwd.html";
}

function updatePWD() {
    event.preventDefault();
    const oldPwd = document.getElementById('oldPwd').value;
    const newPwd = document.getElementById('password').value;
    const confirmation = document.getElementById('confirmation').value;
    const url = '/rest/update/password';
    
    fetch(url, {
        method: 'PUT',
        headers: {
            'Authorization':'Bearer ' + localStorage.getItem("token"),
            'oldPwd': oldPwd,
            'newPwd': newPwd,
            'confirmation': confirmation
        }
    })
    .then (response => {
        if(response.ok) {
            console.log("Password updated")
            alert("Password updated!")
            GoToCorrectHome();
        } else {
            alert("Error")
        }
    })
    .catch(error => {console.log(error)});
}

function getUser() {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const url = '/rest/get/';
    fetch(url + username, {
        method: 'GET'
    })
    .then (response => response.json())
    .then (data => {
        var properties = data.properties;
        document.getElementById("username").value=username;
        document.getElementById("password").value=properties.password.value;
        document.getElementById("role").value=properties.role.value;
        document.getElementById('privacy').value=properties.privacy.value;
        document.getElementById("activity").value=properties.activity.value;
        document.getElementById("name").value=properties.name.value;
        document.getElementById("email").value=properties.email.value;
        document.getElementById("phone").value=properties.phone.value;
        document.getElementById("workplace").value=properties.workplace.value;
        document.getElementById("occupation").value=properties.occupation.value;
        document.getElementById("address").value=properties.address.value;
        document.getElementById("NIF").value=properties.NIF.value;
    })
    .catch(error => {console.log(error)});
}

function updateUser() {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const name = document.getElementById('name').value;
    const email = document.getElementById('email').value;
    const role = document.getElementById('role').value;
    const url = '/rest/update/attributes';

    const privacy = document.getElementById('privacy').value;
    const activity = document.getElementById('activity').value;
    const phone = document.getElementById('phone').value;
    const workplace = document.getElementById('workplace').value;
    const occupation = document.getElementById('occupation').value;
    const address = document.getElementById('address').value;
    const NIF = document.getElementById('NIF').value;

    var bucket = "strong-surfer-379310.appspot.com";
    var file = document.getElementById('photo').files[0];
    var filename = "";
    try{
        var fname = file.name;
        var imageType = fname.split(".");
        filename = username+"Photo."+imageType[imageType.length-1];
    } catch (error) {
           console.log(error);
    }

    const data = new FormData();
    data.append('username', username);
    data.append('password',password);
    data.append('confirmation',password);
    data.append('email', email);
    data.append('name', name);
    data.append('role', role);
    data.append('privacy', privacy);
    data.append('activity', activity);
    data.append('phone', phone);
    data.append('workplace', workplace);
    data.append('address', address);
    data.append('occupation', occupation);
    data.append('NIF', NIF);
    if(!(filename == null) || !(filename == "")) {
        data.append('photo', filename);
    }
    const datajson = {};
    data.forEach((value, key) => (datajson[key] = value));
    console.log("datajson: " + JSON.stringify(datajson));
    fetch(url, {
        method: 'PUT',
        body: JSON.stringify(datajson),
        headers: {
            'Authorization':'Bearer ' + localStorage.getItem("token"),
            'Content-Type': 'application/json'
        }
    })
    .then((response => {
        if(response.ok) {
            if(bucket == null || bucket == "" || filename == null || filename == "") {
                console.log("NO PHOTO ADDED");
            } else {
                var request = new XMLHttpRequest();
                request.open("POST", "/gcs/" + bucket + "/" + filename, false);
                request.setRequestHeader("Content-Type",file.type);
                request.send(file);
                console.log("Photo sent");
            }
            console.log("User updated")
            alert("User updated!")
            GoToCorrectHome();
        } else {
            alert("Error")
        }
    }))
    .catch(error => {console.log(error)});
}

function listUsers() {
    window.location.href = "./listUser.html"
}

function GoToCorrectHome() {
    const role = localStorage.getItem("role");
    if(role == "User") {
        window.location.href = "./../home/homeUser.html";
    } else {
        if(role == "SU") {
            window.location.href = "./../home/homeSU.html";
        } else {
            window.location.href = "./../home/home.html";
        }
    }
}
