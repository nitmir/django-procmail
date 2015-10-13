function on_move(current_view_name, curr_parent_id, curr_id, parent_id, old_index, new_index){
    if(parent_id == curr_parent_id && (curr_id == old_index || curr_id == new_index)){
      if (curr_id == old_index)
          var other_id = new_index
      else
          var other_id = old_index
      if(curr_parent_id){
          var new_id = curr_parent_id + '.' + other_id;
          var old_id = curr_parent_id + '.' + curr_id;
      } else {
          var new_id = other_id;
          var old_id = curr_id;
      }
      curr_id = other_id;
      reverse(current_view_name, args=[new_id]).done(function(data){
          document.location = data + '#scroll=' + document.body.scrollTop;
      });
  } else {
      document.location.hash = '#scroll=' + document.body.scrollTop;
      window.location.reload();
  }
}


function on_list_update(current_view_name, curr_parent_id, curr_id, evt){
    var parent_id = $(evt.item).children("div:first").data("parentid");
    reverse(
        "procmail:move",
        args=[evt.oldIndex, evt.newIndex, parent_id]
    ).fail(function() {
        alert( "error" );
        document.location.hash = '#scroll=' + document.body.scrollTop;
        window.location.reload();
    }).done(function(data) {
        $.ajax(data).done(
            function() {
                on_move(
                    current_view_name,
                    curr_parent_id,
                    curr_id, parent_id,
                    evt.oldIndex,
                    evt.newIndex
                );
            }
        ).fail(function() {
            alert( "error" );
            document.location.hash = '#scroll=' + document.body.scrollTop;
            window.location.reload();
        });
    });
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


