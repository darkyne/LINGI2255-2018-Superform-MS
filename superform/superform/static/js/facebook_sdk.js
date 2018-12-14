 
    
    // This is called with the results from from FB.getLoginStatus().
    var credentials = "";
    function requestPermissionsForPage(callback){
        FB.api (
            "/me/accounts",
            function (response) {
                if(response && !response.error){
                    callback(response);
                }  
            }
        ), {Scope: "manage_pages"};
    } 
    function statusChangeCallback(response) {
        console.log('statusChangeCallback');
        console.log(response);
        // The response object is returned with a status field that lets the
        // app know the current login status of the person.
        // Full docs on the response object can be found in the documentation
        // for FB.getLoginStatus().
        if (response.status === 'connected') {
        // Logged into your app and Facebook.
            requestPermissionsForPage(function(res){
                credentials = res;
                console.log("credentials are : ");
                console.log(credentials)
                $.ajax({
                    type: "POST",
                    contentType:"application/json;charset=utf-8",
                    url:"/facebook_credentials",
                    data: JSON.stringify({credentials}),
                    dataType: "json",
                });
                
            });
        } else {
            console.log('passe dans le else')
        // The person is not logged into your app or we are unable to tell.
        document.getElementById('status').innerHTML = 'Please log ' +
            'into this app.';
        }
        //loginWithPermissions();

    }
    
    // This function is called when someone finishes with the Login
    // Button.  See the onlogin handler attached to it in the sample
    // code below.
    function checkLoginState() {
        FB.getLoginStatus(function(response) {
            statusChangeCallback(response);
        }
        
        );
    }
    
    window.fbAsyncInit = function() {
        FB.init({
        appId      : '523437948128033',
        cookie     : true,  // enable cookies to allow the server to access 
        xfbml      : true,  // parse social plugins on this page
        version    : 'v3.2' // use graph api version 2.8
        });

        // Now that we've initialized the JavaScript SDK, we call 
        // FB.getLoginStatus().  This function gets the state of the
        // person visiting this page and can return one of three states to
        // the callback you provide.  They can be:
        //
        // 1. Logged into your app ('connected')
        // 2. Logged into Facebook, but not your app ('not_authorized')
        // 3. Not logged into Facebook and can't tell if they are logged into
        //    your app or not.
        //
        // These three cases are handled in the callback function.

        /*FB.getLoginStatus(function(response) {
            statusChangeCallback(response);
        });
        */
        

    };

    // Load the SDK asynchronously
    (function(d, s, id) {
        var js, fjs = d.getElementsByTagName(s)[0];
        if (d.getElementById(id)) return;
        js = d.createElement(s); js.id = id;
        js.src = 'https://connect.facebook.net/en_GB/sdk.js#xfbml=1&version=v3.2&appId=523437948128033&autoLogAppEvents=1';
        fjs.parentNode.insertBefore(js, fjs);
      }(document, 'script', 'facebook-jssdk'));

    // Here we run a very simple test of the Graph API after login is
    // successful.  See statusChangeCallback() for when this call is made.
    
    

           