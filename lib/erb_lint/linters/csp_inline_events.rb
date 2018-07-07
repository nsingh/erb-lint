# frozen_string_literal: true

require 'better_html'
require 'better_html/tree/tag'

module ERBLint
  module Linters
    
    # Purpose: 
      # => Avoid inline event handlers on html tags because it violates our Content Security Policy

    # Sample violations caught in *html*.erb templates: 
      # - An html tag like `<a onclick="alert()">` would be caught
      # - `<%= link_to "/url", :onchange => "someFn()" %>` would also be caught
      
    # Limitations: 
      # Currently doesn't catch violations within view helper method calls. But as of the writing
      # there are less than five such violations and those could be corrected manually.
      # We could consider adding future support of traversing helper code.

    class CspInlineEvents < Linter
      include LinterRegistry

      class ConfigSchema < LinterConfig
        property :custom_message, accepts: String        
      end
      self.config_schema = ConfigSchema

      def run(processed_source)
        parser = processed_source.parser

        # Process plain html tags
        parser.nodes_with_type(:tag).each do |tag_node|
          tag = BetterHtml::Tree::Tag.from_node(tag_node)
          next if tag.closing?
          
          inline_events.each do |event_name|
            event_attribute = tag.attributes[event_name]

            if event_attribute.present?
              name_node = tag_node.to_a[1]

              add_offense(
                event_attribute.loc,
                "#{@config.custom_message}\n"\
                "Usage of `#{event_name}` event handler violates our Content Security Policy.\n"\
                "Remove the `#{event_name}` handler and refactor code using `script` tag"
              )
            end
          end
          
          if 'a' == tag.name
            href_attribute = tag.attributes['href']
            if href_attribute.present? && href_attribute.value =~ /javascript.*/
              add_offense(
                href_attribute.loc,
                "#{@config.custom_message}\n"\
                "Usage of javascript URLs in a href=\"\" violates our Content Security Policy.\n"\
                "Replace href=\"#{href_attribute.value}\" with href=\"#\" and refactor code using using `script` tag"
              )
            end
          end
        end

        # Process code within <% .. %> tags
        processed_source.ast.descendants(:erb).each do |erb_node|
            indicator_node, _, code_node, = *erb_node
            indicator = indicator_node&.loc&.source
            code = code_node.children.first
            
            # next unless indicator == '=' # = ignore code that is not being output?
            inline_events = code.match(inline_events_regexp)&.captures
            next unless inline_events.present?
            
            add_offense(
                code_node.loc,
                "#{@config.custom_message}\n"\
                "Usage of inline event handlers #{inline_events.map{|e| '`'+ e +'`'}.join(',')} violates our Content Security Policy\n"\
                "Remove the handler from the helper method and refactor code using `javascript_tag`"
            )
          end
      end

      def inline_events
        # Source: https://www.w3schools.com/jsref/dom_obj_event.asp
        [
          "onchange", #The event occurs when the content of a form element, the selection, or the checked state have changed (for <input>, <select>, and <textarea>)  Event          
          "onclick",  #The event occurs when the user clicks on an element  MouseEvent          
          "onabort",  #The event occurs when the loading of a media is aborted  UiEvent, Event
          "onafterprint", #The event occurs when a page has started printing, or if the print dialogue box has been closed  Event
          "onanimationend", #The event occurs when a CSS animation has completed  AnimationEvent
          "onanimationiteration", #The event occurs when a CSS animation is repeated  AnimationEvent
          "onanimationstart", #The event occurs when a CSS animation has started  AnimationEvent
          "onbeforeprint",  #The event occurs when a page is about to be printed  Event
          "onbeforeunload", #The event occurs before the document is about to be unloaded UiEvent, Event
          "onblur", #The event occurs when an element loses focus FocusEvent
          "oncanplay",  #The event occurs when the browser can start playing the media (when it has buffered enough to begin) Event
          "oncanplaythrough", #The event occurs when the browser can play through the media without stopping for buffering  Event          
          "oncontextmenu",  #The event occurs when the user right-clicks on an element to open a context menu MouseEvent
          "oncopy", #The event occurs when the user copies the content of an element  ClipboardEvent
          "oncut",  #The event occurs when the user cuts the content of an element  ClipboardEvent
          "ondblclick", #The event occurs when the user double-clicks on an element MouseEvent
          "ondrag", #The event occurs when an element is being dragged  DragEvent
          "ondragend",  #The event occurs when the user has finished dragging an element  DragEvent
          "ondragenter",  #The event occurs when the dragged element enters the drop target DragEvent
          "ondragleave",  #The event occurs when the dragged element leaves the drop target DragEvent
          "ondragover", #The event occurs when the dragged element is over the drop target  DragEvent
          "ondragstart",  #The event occurs when the user starts to drag an element DragEvent
          "ondrop", #The event occurs when the dragged element is dropped on the drop target  DragEvent
          "ondurationchange", #The event occurs when the duration of the media is changed Event
          "onended",  #The event occurs when the media has reach the end (useful for messages like "thanks for listening")  Event
          "onerror",  #The event occurs when an error occurs while loading an external file ProgressEvent, UiEvent, Event
          "onfocus",  #The event occurs when an element gets focus  FocusEvent
          "onfocusin",  #The event occurs when an element is about to get focus FocusEvent
          "onfocusout", #The event occurs when an element is about to lose focus  FocusEvent
          "onfullscreenchange", #The event occurs when an element is displayed in fullscreen mode Event
          "onfullscreenerror",  #The event occurs when an element can not be displayed in fullscreen mode Event
          "onhashchange", #The event occurs when there has been changes to the anchor part of a URL HashChangeEvent
          "oninput",  #The event occurs when an element gets user input InputEvent, Event
          "oninvalid",  #The event occurs when an element is invalid  Event
          "onkeydown",  #The event occurs when the user is pressing a key KeyboardEvent
          "onkeypress", #The event occurs when the user presses a key KeyboardEvent
          "onkeyup",  #The event occurs when the user releases a key  KeyboardEvent
          "onload", #The event occurs when an object has loaded UiEvent, Event
          "onloadeddata", #The event occurs when media data is loaded Event
          "onloadedmetadata", #The event occurs when meta data (like dimensions and duration) are loaded  Event
          "onloadstart",  #The event occurs when the browser starts looking for the specified media ProgressEvent
          "onmessage",  #The event occurs when a message is received through the event source Event
          "onmousedown",  #The event occurs when the user presses a mouse button over an element  MouseEvent
          "onmouseenter", #The event occurs when the pointer is moved onto an element MouseEvent
          "onmouseleave", #The event occurs when the pointer is moved out of an element MouseEvent
          "onmousemove",  #The event occurs when the pointer is moving while it is over an element  MouseEvent
          "onmouseover",  #The event occurs when the pointer is moved onto an element, or onto one of its children  MouseEvent
          "onmouseout", #The event occurs when a user moves the mouse pointer out of an element, or out of one of its children  MouseEvent
          "onmouseup",  #The event occurs when a user releases a mouse button over an element MouseEvent
          "onmousewheel", #Deprecated. Use the wheel event instead  WheelEvent
          "onoffline",  #The event occurs when the browser starts to work offline Event
          "ononline", #The event occurs when the browser starts to work online  Event
          "onopen", #The event occurs when a connection with the event source is opened Event
          "onpagehide", #The event occurs when the user navigates away from a webpage PageTransitionEvent
          "onpageshow", #The event occurs when the user navigates to a webpage  PageTransitionEvent
          "onpaste",  #The event occurs when the user pastes some content in an element ClipboardEvent
          "onpause",  #The event occurs when the media is paused either by the user or programmatically Event
          "onplay", #The event occurs when the media has been started or is no longer paused  Event
          "onplaying",  #The event occurs when the media is playing after having been paused or stopped for buffering Event
          "onpopstate", #The event occurs when the window's history changes PopStateEvent
          "onprogress", #The event occurs when the browser is in the process of getting the media data (downloading the media)  Event
          "onratechange", #The event occurs when the playing speed of the media is changed  Event
          "onresize", #The event occurs when the document view is resized UiEvent, Event
          "onreset",  #The event occurs when a form is reset  Event
          "onscroll", #The event occurs when an element's scrollbar is being scrolled UiEvent, Event
          "onsearch", #The event occurs when the user writes something in a search field (for <input="search">) Event
          "onseeked", #The event occurs when the user is finished moving/skipping to a new position in the media  Event
          "onseeking",  #The event occurs when the user starts moving/skipping to a new position in the media Event
          "onselect", #The event occurs after the user selects some text (for <input> and <textarea>) UiEvent, Event
          "onshow", #The event occurs when a <menu> element is shown as a context menu  Event
          "onstalled",  #The event occurs when the browser is trying to get media data, but data is not available Event
          "onstorage",  #The event occurs when a Web Storage area is updated  StorageEvent
          "onsubmit", #The event occurs when a form is submitted  Event
          "onsuspend",  #The event occurs when the browser is intentionally not getting media data  Event
          "ontimeupdate", #The event occurs when the playing position has changed (like when the user fast forwards to a different point in the media)  Event
          "ontoggle", #The event occurs when the user opens or closes the <details> element Event
          "ontouchcancel",  #The event occurs when the touch is interrupted TouchEvent
          "ontouchend", #The event occurs when a finger is removed from a touch screen  TouchEvent
          "ontouchmove",  #The event occurs when a finger is dragged across the screen  TouchEvent
          "ontouchstart", #The event occurs when a finger is placed on a touch screen TouchEvent
          "ontransitionend",  #The event occurs when a CSS transition has completed TransitionEvent
          "onunload", #The event occurs once a page has unloaded (for <body>) UiEvent, Event
          "onvolumechange", #The event occurs when the volume of the media has changed (includes setting the volume to "mute")  Event
          "onwaiting",  #The event occurs when the media has paused but is expected to resume (like when the media pauses to buffer more data)  Event
          "onwheel" #The event occurs when the mouse wheel rolls up or down over an element WheelEvent
        ]
      end

      def inline_events_regexp 
        Regexp.new "(" + inline_events.join("|") + ")", Regexp::IGNORECASE | Regexp::MULTILINE
      end

      def tags(processed_source)
        tag_nodes(processed_source).map { |tag_node| BetterHtml::Tree::Tag.from_node(tag_node) }
      end

      def tag_nodes(processed_source)
        processed_source.parser.nodes_with_type(:tag)
      end

      def autocorrect(_processed_source, offense)        
      end
    end
  end
end
