/**
 *    Copyright 2019 Amazon.com, Inc. or its affiliates
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

var twitch = window.Twitch ? window.Twitch.ext : null;

(function () {
    var token = "";

    if (!twitch) {
        return;
    }

    window.onload = function () {
        document.getElementById("btnCheckAutomod").addEventListener("click", onBtnClick)
    }

    twitch.onAuthorized(function (auth) {
        token = auth.token;

        var btn = document.getElementById("btnCheckAutomod");

        getUser().then(user => {
            // user has shared their identity
            if (user.hasOwnProperty('user_id')) {
                btn.disabled = false
                btn.classList.remove("is-disabled");
                btn.classList.add("is-primary");
            }
            else {
                btn.disabled = true
                btn.classList.remove("is-primary");
                btn.classList.add("is-disabled");
                twitch.actions.requestIdShare();
            }
        })
    });

    onBtnClick = async function () {
        let data = null;

        var input = document.getElementById("txtMessage");

        try {
            const res = await fetch("http://localhost:8080/api/automod", {
                method: "POST",
                headers: {
                    "Authorization": "Bearer " + token,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ message: input.value })
            });
            data = await res.json();
        }
        catch (error) {
            return log("error: ", error);
        }

        var result = document.getElementById("txtResult");
        if(data.is_permitted == true) {
            result.classList.remove("is-error")
            result.classList.add("is-success")
            result.innerHTML = "Message passed AutoMod."
        }
        else {
            result.classList.add("is-error")
            result.classList.remove("is-success") 
            result.innerHTML = "Message did not pass AutoMod."
        }
    }

    // Call EBS to crack open the JWT token and determine if the user has shared their identity
    getUser = async function () {
        try {
            const res = await fetch("http://localhost:8080/api/user", {
                method: "GET",
                headers: {
                    "Authorization": "Bearer " + token
                }
            });
            const data = await res.json();
            return data;
        }
        catch (error) {
            return log("error: ", error);
        }
    }
})()