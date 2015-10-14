function get_id(parent_id, index){
    if(parent_id)
        return parent_id + '.' + index
    else
        return index
}


function do_move(current_view_name, curr_id, old_id, new_id){
    reverse(
        "procmail:move", args=[old_id, new_id, curr_id]
    ).fail(
        function() {
            alert( "error, fail to reverse the procmail:move url" );
            document.location.hash = '#scroll=' + document.body.scrollTop;
            window.location.reload();
        }
    ).done(
        function(move_url) {
            $.ajax(
                move_url
            ).done(
                function(new_curr_id) {
                    if (new_curr_id != curr_id){
                        reverse(
                            current_view_name, args=[new_curr_id]
                        ).done(
                            function(url){
                                document.location = url + '#scroll=' + document.body.scrollTop;
                            }
                        ).fail(
                            function() {
                                alert( "error, fail to reverse the " + current_view_name + " url" );
                                document.location.hash = '#scroll=' + document.body.scrollTop;
                                window.location.reload();
                            }
                        );
                    } else {
                        document.location.hash = '#scroll=' + document.body.scrollTop;
                        window.location.reload();
                    }
                }
            ).fail(
                function() {
                    alert( "error, fail to move statement (url " + move_url + ")" );
                    document.location.hash = '#scroll=' + document.body.scrollTop;
                    window.location.reload();
                }
            );
        }
    );
}


function getUrlHashParameter(sParam) {
    var sPageURL = decodeURIComponent(window.location.hash.substring(1)),
        sURLVariables = sPageURL.split('&'),
        sParameterName,
        i;

    for (i = 0; i < sURLVariables.length; i++) {
        sParameterName = sURLVariables[i].split('=');

        if (sParameterName[0] === sParam) {
            return sParameterName[1] === undefined ? true : sParameterName[1];
        }
    }
}


