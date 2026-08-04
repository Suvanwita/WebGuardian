// WebGuardian Password Strength Checker
(function () {
  // Mocked import of calculateEntropy matching utils/entropy.js
  function calculateEntropy(password) {
    if (!password || password.length === 0) {
      return "Weak";
    }

    const length = password.length;
    let poolSize = 0;

    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;

    if (poolSize === 0) {
      return "Weak";
    }

    const entropy = length * Math.log2(poolSize);

    if (entropy < 40) {
      return "Weak";
    } else if (entropy < 80) {
      return "Medium";
    } else {
      return "Strong";
    }
  }

  const badgeMap = new WeakMap();

  function getOrCreateBadge(input) {
    if (badgeMap.has(input)) {
      return badgeMap.get(input);
    }

    const badge = document.createElement('div');
    badge.className = 'webguardian-password-badge';
    
    // Premium Styling
    badge.style.position = 'absolute';
    badge.style.zIndex = '999999';
    badge.style.pointerEvents = 'none';
    badge.style.padding = '4px 8px';
    badge.style.borderRadius = '4px';
    badge.style.fontSize = '11px';
    badge.style.fontWeight = 'bold';
    badge.style.fontFamily = 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
    badge.style.color = '#ffffff';
    badge.style.boxShadow = '0 2px 8px rgba(0,0,0,0.15)';
    badge.style.transition = 'opacity 0.15s ease, transform 0.15s ease';
    badge.style.opacity = '0';
    badge.style.transform = 'translateY(5px)';
    
    document.body.appendChild(badge);
    badgeMap.set(input, badge);
    return badge;
  }

  function positionBadge(input, badge) {
    const rect = input.getBoundingClientRect();
    const badgeHeight = badge.offsetHeight || 22; // fallback if not yet rendered
    
    // Position floating right next to the input field, centered vertically
    const top = rect.top + window.scrollY + (rect.height - badgeHeight) / 2;
    const left = rect.right + window.scrollX + 8;
    
    badge.style.top = `${top}px`;
    badge.style.left = `${left}px`;
  }

  function updateBadge(input) {
    const badge = getOrCreateBadge(input);
    const value = input.value;
    
    if (!value) {
      badge.style.opacity = '0';
      badge.style.transform = 'translateY(5px)';
      return;
    }

    const strength = calculateEntropy(value);
    badge.textContent = strength;

    // Apply colors based on strength
    if (strength === 'Weak') {
      badge.style.backgroundColor = '#ef4444'; // Red
      badge.style.boxShadow = '0 2px 8px rgba(239, 68, 68, 0.3)';
    } else if (strength === 'Medium') {
      badge.style.backgroundColor = '#f59e0b'; // Amber/Orange
      badge.style.boxShadow = '0 2px 8px rgba(245, 158, 11, 0.3)';
    } else {
      badge.style.backgroundColor = '#10b981'; // Green
      badge.style.boxShadow = '0 2px 8px rgba(16, 185, 129, 0.3)';
    }

    badge.style.opacity = '1';
    badge.style.transform = 'translateY(0)';
    positionBadge(input, badge);
  }

  // Delegated event listener for user input
  document.addEventListener('input', (event) => {
    const target = event.target;
    if (target && target.tagName === 'INPUT' && target.type === 'password') {
      updateBadge(target);
    }
  });

  // Show badge on focus (if text is present)
  document.addEventListener('focusin', (event) => {
    const target = event.target;
    if (target && target.tagName === 'INPUT' && target.type === 'password') {
      updateBadge(target);
    }
  });

  // Hide badge on blur
  document.addEventListener('focusout', (event) => {
    const target = event.target;
    if (target && target.tagName === 'INPUT' && target.type === 'password') {
      const badge = badgeMap.get(target);
      if (badge) {
        badge.style.opacity = '0';
        badge.style.transform = 'translateY(5px)';
      }
    }
  });

  // Handle window resizing and scrolling to reposition active badges
  window.addEventListener('resize', () => {
    const activeElement = document.activeElement;
    if (activeElement && activeElement.tagName === 'INPUT' && activeElement.type === 'password') {
      const badge = badgeMap.get(activeElement);
      if (badge) {
        positionBadge(activeElement, badge);
      }
    }
  });

  window.addEventListener('scroll', () => {
    const activeElement = document.activeElement;
    if (activeElement && activeElement.tagName === 'INPUT' && activeElement.type === 'password') {
      const badge = badgeMap.get(activeElement);
      if (badge) {
        positionBadge(activeElement, badge);
      }
    }
  }, true); // Use capture to handle scrolling in nested elements
})();
