$(document).ready(
    function() {
        // styling
        $('#procmailrc').css('max-height',get_screen_size().y);
        $( window ).resize(
            function (){
                $('#procmailrc').css('max-height',get_screen_size().y);
                scroll_list = $('#procmailrc').scrollTop();
            }
        );
        $('#procmailrc').css({
            'position':'absolute',
            'top':'0px',
        });
        $(window).scroll(
            function (){
                $('#procmailrc').css({
                    'top': $(this).scrollTop()
                });
            }
        );
        $('#main').css('margin-left', $('#procmailrc').width() + 20);
        
        //Scroll
        var scroll = parseInt(getUrlHashParameter("scroll"));
        var scroll_list = parseInt(getUrlHashParameter("scroll_list"));
        if(scroll)
            $('body').scrollTop(scroll);
        if(scroll_list)
            $('#procmailrc').scrollTop(scroll_list);
        $('#procmailrc').scroll(
            function (){
                document.location.hash = build_hash();
            }
        );
        $(window).scroll(
            function (){
                document.location.hash = build_hash();
            }
        );
        
        $('.keep_scroll_list').click(
          function(){
            var url = $(this).attr('href');
            $(this).attr('href', url + '#scroll_list=' + $('#procmailrc').scrollTop());
            return true;
          }
        );
        
        //hide up/down button if javascript drag an drop supported
        $(".up_down").each(
            function() {
                $(this).hide()
            }
        );

    }
);
