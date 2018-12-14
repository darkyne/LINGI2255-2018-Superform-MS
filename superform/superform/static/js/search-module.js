
/*
* waitJQuery : launch a function based on JQuery when JQuery is loaded
* @params : func, the function to launch, args : its arguments
* @return : undefined
*/

function waitJQuery(func, args) {
    if (window.jQuery)
         func(args);
    else
        setTimeout(function() {
            waitJQuery(func, args)
        }, 40);
}

/*
* loadSearchTemplate : load the html based on fields
* @params : fields, the input fields
* @returns : html loaded
*/
function loadSearchTemplate(fields) {
    var template = '';

    fields.forEach(function(item, number) {
        if (number == 1) {
            template += createSearchInput(item, typeFields[item] == undefined ? "text" : typeFields[item]);
            template += '<button type="button" class="btn btn-success" data-toggle="collapse" data-target="#demo" aria-expanded="true">Advanced search &gt;&gt;</button>'
        }

    });

    $("#"+search_id).html(template);
}

function createSearchInput(name, type) {
    input = '<div class="form-group"> <label for='+name+'><b>Search by subject :</b></label>';
          <input type="text" class="form-control" id="usr" placeholder="...">
          <div class="input-group-btn">
      <button type="button" class="btn btn-success" data-toggle="collapse" data-target="#demo" aria-expanded="true">Advanced search &gt;&gt;</button>
          </div>
        </div>';
}







waitJQuery(loadSearchTemplate, fields);

