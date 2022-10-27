// alertmon.js
$(alertmon = function() {


  var target_template = _.template(' \
    <div id="target_<%= i %>" class="row"> \
      <% if (remove_button === true) { %> \
      <div class="col-md-10"> \
      <% } else { %> \
      <div class="col-md-12"> \
      <% } %> \
        <input type="text" class="form-control" \
        id="alert_query_<%= i %>" \
        name="alert_query_<%= i %>" \
        value="<%= value %>" \
        placeholder="alert_query_<%= i %>"> \
      </div> \
      <% if (remove_button === true) { %> \
      <div class="col-md-2"> \
        <a id="remove_target_<%= i %>" href="#"> (Remove)</a> \
      </div> \
      <% } %> \
    </div>');

  var alertForm = {
    num_targets: function() {
      return $('#graphite_targets input').size();
    },
    create_target: function(spec) {
      if (spec !== undefined) {
        var i = spec.target_id,
            remove_button = spec.remove_button,
            value = spec.value;
      } else {
        var i = alertForm.num_targets() + 1,
            value = "",
            remove_button = true;
      }
      var safeEscapedGraphiteTarget = value.replace(/\"/g, "&quot;");
      return(target_template({i:i, value: safeEscapedGraphiteTarget, remove_button:remove_button}));
    },
    create_inclusive_list: function(from, until) {
      var result = [];
      for (i = from; i <= until; i++) {
        result.push(i);
      }
      return result;
    },
    enable_inputs: function(input_list) {
      _.each(input_list, function(x) {
        $(x).attr("disabled", false);
      });
    },
    disable_inputs: function(input_list) {
      _.each(input_list, function(x) {
        $(x).attr("disabled", true);
      });
    },
    disable_warn_threshold: function() {
      this.disable_inputs(["#warn_thresh_num", "#warn_trigger_type",
        "#warn_trigger_value", "#warn_mail_list"]);
    },
    enable_warn_threshold: function() {
      this.enable_inputs(["#warn_thresh_num", "#warn_trigger_type",
        "#warn_trigger_value", "#warn_mail_list"]);
    },
    disable_crit_threshold: function() {
      this.disable_inputs(["#crit_thresh_num", "#crit_trigger_type",
        "#crit_trigger_value", "#crit_mail_list"]);
    },
    enable_crit_threshold: function() {
      this.enable_inputs(["#crit_thresh_num", "#crit_trigger_type",
        "#crit_trigger_value", "#crit_mail_list"]);
    }
  };

  _.extend(alertForm, Backbone.Events);

  // adding and removing target form elements

  alertForm.on("target:add", function(spec) {
    $(alertForm.create_target(spec)).appendTo($('#graphite_targets'));
    var new_rm_target_id = "#remove_target_" + alertForm.num_targets(),
        new_target_id = "#target_" + alertForm.num_targets(),
        new_target_num = alertForm.num_targets();
    $(new_rm_target_id).click( function() {
      alertForm.trigger("target:rm", new_target_id, new_target_num);
    });
  });

  alertForm.on("target:rm", function(target_id, target_num) {
    var fix_from = target_num + 1,
        fix_until = alertForm.num_targets();
    $(target_id).remove();
    if (fix_from <= fix_until) {
      _.each(alertForm.create_inclusive_list(fix_from, fix_until), function(x) {
        var down_alert_query_id = "alert_query_" + (x-1),
            down_remove_target_id = "remove_target_" + (x-1),
            alert_query_id = "alert_query_" + x,
            remove_target_id = "remove_target_" + x,
            target_id = "target_" + x,
            down_target_id = "target_" + (x-1);

        $("#" + target_id).attr('id', down_target_id);
        $("#" + alert_query_id).attr('placeholder', down_alert_query_id);
        $("#" + alert_query_id).attr('name', down_alert_query_id);
        $("#" + alert_query_id).attr('id', down_alert_query_id);
        $("#" + remove_target_id).attr('id', down_remove_target_id);
        $("#" + down_remove_target_id).unbind();
        $("#" + down_remove_target_id).click( function() {
            alertForm.trigger("target:rm", "#" + down_target_id, (x-1));
        });
      });
    }
  });

  $('#add_target').click( function() {
    alertForm.trigger("target:add");
  });

  $('button.check_firing').click( function(event) {
    var id = event.target.id;
    $('#' + id + '_status').load('/api/v0/alert/' + id + '/check');
  });

  // enabling and disabling threshold definitions based on if they are used or unused

  // initial page load
  if ($("#warn_thresh_op").val() === "unused") {
    alertForm.disable_warn_threshold();
  } else {
    alertForm.enable_warn_threshold();
  }
  if ($("#crit_thresh_op").val() === "unused") {
    alertForm.disable_crit_threshold();
  } else {
    alertForm.enable_crit_threshold();
  }

  // await changes
  $('#warn_thresh_op').change(function () {
    if ($(this).val() === "unused") {
      alertForm.disable_warn_threshold();
    } else {
      alertForm.enable_warn_threshold();
    }
  });
  $('#crit_thresh_op').change(function () {
    if ($(this).val() === "unused") {
      alertForm.disable_crit_threshold();
    } else {
      alertForm.enable_crit_threshold();
    }
  });

  return({
    add_target: function(spec) {
      alertForm.trigger("target:add", spec);
    }
  });

}());
