function GoToRegister() {
    window.location.href = "./auth/register.html";
}

function GoToLogin() {
    window.location.href = "./auth/login.html";
}

function register() {
            event.preventDefault();
            const username = document.getElementById('username').value;
            const name = document.getElementById('name').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const confirmation = document.getElementById('confirmation').value;
            const url = '/rest/register';

            const privacy = document.getElementById('privacy').value;
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
            data.append('password', password);
            data.append('confirmation', confirmation);
            data.append('email', email);
            data.append('name', name);
            data.append('role', 'User');
            data.append('privacy', privacy);
            data.append('activity', 'Inactive');
            data.append('phone', phone);
            data.append('workplace', workplace);
            data.append('address', address);
            data.append('occupation', occupation);
            data.append('NIF', NIF);
            data.append('photo', filename);
            const datajson = {};
            data.forEach((value, key) => (datajson[key] = value));
            console.log("datajson: " + JSON.stringify(datajson));
            fetch(url, {
                method: 'POST',
                body: JSON.stringify(datajson),
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then (response => {
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
                    window.location.href = "./../index.html";
                } else {
                    alert("Registration failed");
                }
            })

}

function login() {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const url = '/rest/login';

    const data = new FormData();
    data.append('username', username);
    data.append('password', password);
    const datajson = {};
    data.forEach((value, key) => (datajson[key] = value));
    console.log("datajson: " + JSON.stringify(datajson));
    fetch(url, {
        method: 'POST',
        body: JSON.stringify(datajson),
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then (response => response.json())
    .then (data =>{
        console.log(JSON.stringify(data));
        if(data.tokenID != null) {
            console.log("token: " + data.tokenID);
            localStorage.setItem("token", data.tokenID);
            localStorage.setItem("username", data.username);
            localStorage.setItem("role", data.role);
            if(data.role == "User") {
                window.location.href = "./../home/homeUser.html";
            } else if(data.role == "SU") {
                window.location.href = "./../home/homeSU.html";
            } else {
                window.location.href = "./../home/home.html";
            }
        } else {
            alert("Login Failed!")
        }

    })
    .catch(error => {console.log(error)});

}