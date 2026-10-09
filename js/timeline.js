(function () {
  function formatTimestamp(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value || 'Unknown';
    return date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
  }

  function groupTimelineByDay(events) {
    return events.reduce((groups, event) => {
      const key = new Date(event.timestamp).toISOString().slice(0, 10);
      if (!groups[key]) groups[key] = [];
      groups[key].push(event);
      return groups;
    }, {});
  }

  window.Timeline = {
    formatTimestamp,
    groupTimelineByDay
  };
})();
