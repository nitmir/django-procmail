function get_id(parent_id, index){
    if(parent_id)
        return parent_id + '.' + index
    else
        return index
}

function build_hash(){
    return '#scroll=' + document.body.scrollTop + '&scroll_list=' + $('#procmailrc').scrollTop();
}

function do_move(current_view_name, curr_id, old_id, new_id){
    reverse(
        "procmail:move", args=[old_id, new_id, curr_id]
    ).fail(
        function() {
            alert( "error, fail to reverse the procmail:move url" );
            document.location.hash = build_hash();
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
                                document.location = url + build_hash();
                            }
                        ).fail(
                            function() {
                                alert( "error, fail to reverse the " + current_view_name + " url" );
                                document.location.hash = build_hash();
                                window.location.reload();
                            }
                        );
                    } else {
                        document.location.hash = build_hash();
                        window.location.reload();
                    }
                }
            ).fail(
                function() {
                    alert( "error, fail to move statement (url " + move_url + ")" );
                    document.location.hash = build_hash();
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

function get_screen_size(){
    var w = window,
    d = document,
    e = d.documentElement,
    g = d.getElementsByTagName('body')[0],
    x = w.innerWidth || e.clientWidth || g.clientWidth,
    y = w.innerHeight|| e.clientHeight|| g.clientHeight;
    return {x:x,y:y}
}
