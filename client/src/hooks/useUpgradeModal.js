import { useState } from "react";

export default function useUpgradeModal() {
  const [open, setOpen] = useState(false);
  const [feature, setFeature] = useState(null);

  const showUpgrade = (featureKey) => {
    setFeature(featureKey);
    setOpen(true);
  };

  const closeUpgrade = () => {
    setOpen(false);
    setFeature(null);
  };

  return {
    open,
    feature,
    showUpgrade,
    closeUpgrade,
  };
}