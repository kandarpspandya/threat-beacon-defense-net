
import { forwardRef } from "react";

export interface UserIconProps extends React.SVGAttributes<SVGSVGElement> {}

const UserIcon = forwardRef<SVGSVGElement, UserIconProps>((props, ref) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      ref={ref}
      {...props}
    >
      <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  );
});

UserIcon.displayName = "UserIcon";

export { UserIcon };
