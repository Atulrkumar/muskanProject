#!/usr/bin/env python3
import sys
import time
import subprocess
from vulnerability_scanner import VulnerabilityScanner

def main():
    # Banner
    print("""
    #########################################################
    #                                                       #
    #           Vulnerability Scanner (Terminal)            #
    #                                                       #
    #########################################################
    """)
    
    # Get target from command line or prompt
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target to scan: ")
    
    # Remove @ symbol if present
    if '@' in target:
        target = target.split('@')[1]
    
    # Create scanner
    print("\nInitializing scanner...")
    scanner = VulnerabilityScanner()
    
    # Run direct Nmap scan first for immediate feedback
    print(f"\nRunning direct Nmap scan of {target}...")
    try:
        nmap_process = subprocess.run(
            ["nmap", "-F", "-sV", target],
            capture_output=True,
            text=True,
            check=False
        )
        print("\n--- Direct Nmap Scan Results ---\n")
        print(nmap_process.stdout)
    except Exception as e:
        print(f"Error running direct Nmap scan: {e}")
    
    # Start vulnerability scan
    print(f"\nStarting vulnerability analysis for {target}...")
    print("This may take up to 30 seconds...\n")
    start_time = time.time()
    
    # Run the scan
    results = scanner.scan_target(target)
    
    # Calculate scan time
    scan_time = time.time() - start_time
    
    if not results:
        print("Vulnerability scan failed or returned no results.")
        return
    
    # Display results
    print(f"\nVulnerability analysis completed in {scan_time:.2f} seconds\n")
    
    # Generate and display report
    report = scanner.generate_report(results)
    print(report)
    
    # Save results
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{target.replace('.', '-')}_{timestamp}"
    
    # Save as JSON
    json_path = f"{filename}.json"
    scanner.save_results(results, 'json')
    
    # Save as TXT
    txt_path = f"{filename}.txt"
    scanner.save_results(results, 'txt')
    
    print(f"\nResults saved to {json_path} and {txt_path}")
    
    # Show summary of the scan
    print("\n--- Scan Summary ---")
    print(f"Target: {target}")
    print(f"Open Ports: {', '.join(map(str, results['open_ports']))}")
    print(f"Services: {len(results['services'])}")
    print(f"Potential Vulnerabilities: {len(results['cves'])}")
    
    direct_matches = len([cve for cve in results['cves'] if cve['match_type'] == 'direct'])
    predicted_matches = len([cve for cve in results['cves'] if cve['match_type'] == 'predicted'])
    print(f"Direct Matches: {direct_matches}")
    print(f"ML-Predicted: {predicted_matches}")

if __name__ == "__main__":
    main() 